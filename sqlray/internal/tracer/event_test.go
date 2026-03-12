package tracer

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"strings"
	"testing"
)

func TestDecodeEvent(t *testing.T) {
	raw := make([]byte, EventSize)
	binary.LittleEndian.PutUint32(raw[0:], 1234)
	binary.LittleEndian.PutUint32(raw[4:], 9)
	binary.LittleEndian.PutUint32(raw[8:], EventQuery)
	copy(raw[12:], "SELECT 1\x00")

	event, err := DecodeEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	if event.Pid != 1234 {
		t.Errorf("Pid = %d, want 1234", event.Pid)
	}
	if event.Len != 9 {
		t.Errorf("Len = %d, want 9", event.Len)
	}
	if event.EventType != EventQuery {
		t.Errorf("EventType = %d, want %d", event.EventType, EventQuery)
	}
	if got := TrimNull(event.Buf[:event.Len]); got != "SELECT 1" {
		t.Errorf("Buf = %q, want %q", got, "SELECT 1")
	}
}

func TestDecodeEventTooShort(t *testing.T) {
	_, err := DecodeEvent([]byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for short input")
	}
}

func TestExtractQueryEmptyStmtName(t *testing.T) {
	data := []byte("\x00SELECT $1\x00\x00\x01\x00\x00\x00\x00")
	name, got := ExtractQuery(data)
	if name != "" {
		t.Errorf("stmt name = %q, want empty", name)
	}
	if got != "SELECT $1" {
		t.Errorf("got %q, want %q", got, "SELECT $1")
	}
}

func TestExtractQueryNamedStmt(t *testing.T) {
	data := append([]byte("my_stmt\x00"), []byte("SELECT $1\x00\x00\x01\x00\x00\x00\x00")...)
	name, got := ExtractQuery(data)
	if name != "my_stmt" {
		t.Errorf("stmt name = %q, want %q", name, "my_stmt")
	}
	if got != "SELECT $1" {
		t.Errorf("got %q, want %q", got, "SELECT $1")
	}
}

func TestExtractQueryEmpty(t *testing.T) {
	data := []byte("\x00\x00")
	_, got := ExtractQuery(data)
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	fn()
	w.Close()
	out, _ := io.ReadAll(r)
	os.Stdout = old
	return string(out)
}

func toBuf(data []byte) [MaxSQLLen]byte {
	var buf [MaxSQLLen]byte
	copy(buf[:], data)
	return buf
}

func TestHandleEventMultiplePreparedStatements(t *testing.T) {
	// Reset global state
	queryTemplates = make(map[stmtKey]string)

	pid := uint32(1234)

	// Parse "s1" → "SELECT $1"
	parseData1 := []byte("s1\x00SELECT $1\x00\x00\x00")
	HandleEvent(&Event{
		Pid:       pid,
		Len:       uint32(len(parseData1)),
		EventType: EventParse,
		Buf:       toBuf(parseData1),
	})

	// Parse "s2" → "SELECT $1, $2" (same PID, different statement)
	parseData2 := []byte("s2\x00SELECT $1, $2\x00\x00\x00")
	HandleEvent(&Event{
		Pid:       pid,
		Len:       uint32(len(parseData2)),
		EventType: EventParse,
		Buf:       toBuf(parseData2),
	})

	// Bind for "s1" with param "hello"
	var bindPayload1 bytes.Buffer
	bindPayload1.WriteString("\x00")                        // portal (unnamed)
	bindPayload1.WriteString("s1\x00")                      // statement name
	bindPayload1.Write([]byte{0, 0})                        // 0 format codes
	bindPayload1.Write([]byte{0, 1})                        // 1 param
	binary.Write(&bindPayload1, binary.BigEndian, int32(5)) // param len
	bindPayload1.WriteString("hello")

	output1 := captureStdout(t, func() {
		HandleEvent(&Event{
			Pid:       pid,
			Len:       uint32(bindPayload1.Len()),
			EventType: EventBind,
			Buf:       toBuf(bindPayload1.Bytes()),
		})
	})

	// Should produce "SELECT 'hello'" from s1's template, not s2's
	if !strings.Contains(output1, "SELECT 'hello'") {
		t.Errorf("bind for s1: got %q, want output containing \"SELECT 'hello'\"", output1)
	}
	if strings.Contains(output1, "$2") {
		t.Errorf("bind for s1 used s2's template: %q", output1)
	}

	// Bind for "s2" with params "a", "b"
	var bindPayload2 bytes.Buffer
	bindPayload2.WriteString("\x00")   // portal
	bindPayload2.WriteString("s2\x00") // statement name
	bindPayload2.Write([]byte{0, 0})   // 0 format codes
	bindPayload2.Write([]byte{0, 2})   // 2 params
	binary.Write(&bindPayload2, binary.BigEndian, int32(1))
	bindPayload2.WriteString("a")
	binary.Write(&bindPayload2, binary.BigEndian, int32(1))
	bindPayload2.WriteString("b")

	output2 := captureStdout(t, func() {
		HandleEvent(&Event{
			Pid:       pid,
			Len:       uint32(bindPayload2.Len()),
			EventType: EventBind,
			Buf:       toBuf(bindPayload2.Bytes()),
		})
	})

	if !strings.Contains(output2, "SELECT 'a', 'b'") {
		t.Errorf("bind for s2: got %q, want output containing \"SELECT 'a', 'b'\"", output2)
	}
}

func TestTrimNull(t *testing.T) {
	tests := []struct {
		in   []byte
		want string
	}{
		{[]byte("hello\x00\x00\x00"), "hello"},
		{[]byte("hello"), "hello"},
		{[]byte("\x00"), ""},
		{[]byte{}, ""},
	}
	for _, tt := range tests {
		if got := TrimNull(tt.in); got != tt.want {
			t.Errorf("trimNull(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
