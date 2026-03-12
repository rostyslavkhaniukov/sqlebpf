//go:build integration

package tests

import (
	"encoding/binary"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"sqlray/internal/tracer"
)

type testFixture struct {
	objs     tracer.BPFObjects
	links    []link.Link
	rd       *ringbuf.Reader
	events   chan *tracer.Event
	serverFd int
	clientFd int
	acceptFd int
}

func setupFixture(t *testing.T) *testFixture {
	t.Helper()

	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("removing memlock: %v", err)
	}

	objs, links, rd, err := tracer.LoadBPF()
	if err != nil {
		t.Fatalf("loading BPF: %v", err)
	}

	serverFd, clientFd, acceptFd := createSocketPair(t)

	f := &testFixture{
		objs:     objs,
		links:    links,
		rd:       rd,
		events:   make(chan *tracer.Event, 100),
		serverFd: serverFd,
		clientFd: clientFd,
		acceptFd: acceptFd,
	}

	go func() {
		var rec ringbuf.Record
		for {
			if err := rd.ReadInto(&rec); err != nil {
				return
			}
			event, err := tracer.DecodeEvent(rec.RawSample)
			if err != nil {
				continue
			}
			f.events <- event
		}
	}()

	return f
}

func (f *testFixture) close() {
	f.rd.Close()
	tracer.CloseLinks(f.links)
	f.objs.Close()
	syscall.Close(f.acceptFd)
	syscall.Close(f.clientFd)
	syscall.Close(f.serverFd)
}

func (f *testFixture) sendAndReceive(t *testing.T, data []byte) {
	t.Helper()
	if _, err := syscall.Write(f.clientFd, data); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4096)
	if _, _, err := syscall.Recvfrom(f.acceptFd, buf, 0); err != nil {
		t.Fatalf("recvfrom: %v", err)
	}
}

func (f *testFixture) waitForEvent(t *testing.T, wantType uint32, timeout time.Duration) *tracer.Event {
	t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case event := <-f.events:
			if event.EventType == wantType {
				return event
			}
		case <-timer.C:
			t.Fatalf("timeout waiting for event type %d", wantType)
			return nil
		}
	}
}

func TestBPFSimpleQuery(t *testing.T) {
	f := setupFixture(t)
	defer f.close()

	msg := buildSimpleQuery("SELECT 1")
	f.sendAndReceive(t, msg)

	event := f.waitForEvent(t, tracer.EventQuery, 2*time.Second)
	sql := tracer.TrimNull(event.Buf[:event.Len])
	if sql != "SELECT 1" {
		t.Errorf("SQL = %q, want %q", sql, "SELECT 1")
	}
}

func TestBPFBatchedMessages(t *testing.T) {
	f := setupFixture(t)
	defer f.close()

	parseMsg := buildParseMessage("", "SELECT $1")
	bindMsg := buildBindMessage("", "", []string{"42"})
	syncMsg := buildSyncMessage()
	batch := concat(parseMsg, bindMsg, syncMsg)

	f.sendAndReceive(t, batch)

	parseEvent := f.waitForEvent(t, tracer.EventParse, 2*time.Second)
	_, query := tracer.ExtractQuery(parseEvent.Buf[:parseEvent.Len])
	if query != "SELECT $1" {
		t.Errorf("Parse query = %q, want %q", query, "SELECT $1")
	}

	bindEvent := f.waitForEvent(t, tracer.EventBind, 2*time.Second)
	params, err := tracer.ParseBindParams(bindEvent.Buf[:bindEvent.Len])
	if err != nil {
		t.Fatalf("parsing bind params: %v", err)
	}
	if len(params) != 1 || params[0] != "42" {
		t.Errorf("params = %v, want [42]", params)
	}
}

func TestBPFNamedPreparedStatement(t *testing.T) {
	f := setupFixture(t)
	defer f.close()

	parseMsg := buildParseMessage("my_stmt", "SELECT $1, $2")
	bindMsg := buildBindMessage("", "my_stmt", []string{"hello", "world"})
	batch := concat(parseMsg, bindMsg)

	f.sendAndReceive(t, batch)

	parseEvent := f.waitForEvent(t, tracer.EventParse, 2*time.Second)
	_, query := tracer.ExtractQuery(parseEvent.Buf[:parseEvent.Len])
	if query != "SELECT $1, $2" {
		t.Errorf("Parse query = %q, want %q", query, "SELECT $1, $2")
	}
}

func createSocketPair(t *testing.T) (serverFd, clientFd, acceptFd int) {
	t.Helper()

	var err error
	serverFd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("creating server socket: %v", err)
	}
	syscall.SetsockoptInt(serverFd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)

	if err := syscall.Bind(serverFd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if err := syscall.Listen(serverFd, 1); err != nil {
		t.Fatalf("listen: %v", err)
	}

	sa, err := syscall.Getsockname(serverFd)
	if err != nil {
		t.Fatalf("getsockname: %v", err)
	}
	port := sa.(*syscall.SockaddrInet4).Port

	clientFd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("creating client socket: %v", err)
	}
	if err := syscall.Connect(clientFd, &syscall.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatalf("connect: %v", err)
	}

	acceptFd, _, err = syscall.Accept(serverFd)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}

	return serverFd, clientFd, acceptFd
}

func buildSimpleQuery(sql string) []byte {
	payload := sql + "\x00"
	msgLen := uint32(4 + len(payload))
	buf := make([]byte, 1+4+len(payload))
	buf[0] = 'Q'
	binary.BigEndian.PutUint32(buf[1:5], msgLen)
	copy(buf[5:], payload)
	return buf
}

func buildParseMessage(stmtName, query string) []byte {
	payload := stmtName + "\x00" + query + "\x00" + "\x00\x00"
	msgLen := uint32(4 + len(payload))
	buf := make([]byte, 1+4+len(payload))
	buf[0] = 'P'
	binary.BigEndian.PutUint32(buf[1:5], msgLen)
	copy(buf[5:], payload)
	return buf
}

func buildBindMessage(portal, stmt string, params []string) []byte {
	var payload []byte
	payload = append(payload, portal...)
	payload = append(payload, 0)
	payload = append(payload, stmt...)
	payload = append(payload, 0)
	payload = append(payload, 0, 0) // 0 format codes
	payload = binary.BigEndian.AppendUint16(payload, uint16(len(params)))
	for _, p := range params {
		payload = binary.BigEndian.AppendUint32(payload, uint32(len(p)))
		payload = append(payload, p...)
	}
	payload = append(payload, 0, 0) // 0 result format codes

	msgLen := uint32(4 + len(payload))
	buf := make([]byte, 1+4+len(payload))
	buf[0] = 'B'
	binary.BigEndian.PutUint32(buf[1:5], msgLen)
	copy(buf[5:], payload)
	return buf
}

func buildSyncMessage() []byte {
	return []byte{'S', 0, 0, 0, 4}
}

func concat(slices ...[]byte) []byte {
	var out []byte
	for _, s := range slices {
		out = append(out, s...)
	}
	return out
}
