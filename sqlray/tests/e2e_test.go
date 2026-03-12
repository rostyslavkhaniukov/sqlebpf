//go:build e2e

package tests

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/jackc/pgx/v5"

	"sqlray/internal/tracer"
)

type e2eFixture struct {
	objs   tracer.BPFObjects
	links  []link.Link
	rd     *ringbuf.Reader
	events chan *tracer.Event
	conn   *pgx.Conn
}

func setupE2E(t *testing.T) *e2eFixture {
	t.Helper()

	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("removing memlock: %v", err)
	}

	objs, links, rd, err := tracer.LoadBPF()
	if err != nil {
		t.Fatalf("loading BPF: %v", err)
	}

	dsn := os.Getenv("POSTGRES_URL")
	if dsn == "" {
		dsn = "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable"
	}

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		rd.Close()
		tracer.CloseLinks(links)
		objs.Close()
		t.Fatalf("connecting to postgres: %v", err)
	}

	f := &e2eFixture{
		objs:   objs,
		links:  links,
		rd:     rd,
		events: make(chan *tracer.Event, 100),
		conn:   conn,
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

func (f *e2eFixture) close() {
	f.conn.Close(context.Background())
	f.rd.Close()
	tracer.CloseLinks(f.links)
	f.objs.Close()
}

func (f *e2eFixture) waitForEvent(t *testing.T, wantType uint32, timeout time.Duration) *tracer.Event {
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

func (f *e2eFixture) drain() {
	for len(f.events) > 0 {
		<-f.events
	}
}

func TestE2ESimpleProtocol(t *testing.T) {
	f := setupE2E(t)
	defer f.close()

	ctx := context.Background()
	var result int
	err := f.conn.QueryRow(ctx, "SELECT $1::int", pgx.QueryExecModeSimpleProtocol, 42).Scan(&result)
	if err != nil {
		t.Fatalf("query: %v", err)
	}

	event := f.waitForEvent(t, tracer.EventQuery, 3*time.Second)
	sql := tracer.TrimNull(event.Buf[:event.Len])
	if sql != "SELECT  '42' ::int" {
		t.Errorf("captured SQL = %q, want %q", sql, "SELECT  '42' ::int")
	}
}

func TestE2EExtendedQuery(t *testing.T) {
	f := setupE2E(t)
	defer f.close()

	ctx := context.Background()
	var result int
	err := f.conn.QueryRow(ctx, "SELECT $1::int", 42).Scan(&result)
	if err != nil {
		t.Fatalf("query: %v", err)
	}

	parseEvent := f.waitForEvent(t, tracer.EventParse, 3*time.Second)
	_, query := tracer.ExtractQuery(parseEvent.Buf[:parseEvent.Len])
	if query != "SELECT $1::int" {
		t.Errorf("captured query = %q, want %q", query, "SELECT $1::int")
	}

	bindEvent := f.waitForEvent(t, tracer.EventBind, 3*time.Second)
	if bindEvent == nil {
		t.Fatal("expected bind event")
	}
}

func TestE2ETextParams(t *testing.T) {
	f := setupE2E(t)
	defer f.close()

	ctx := context.Background()
	var result string
	err := f.conn.QueryRow(ctx, "SELECT $1::text", "hello").Scan(&result)
	if err != nil {
		t.Fatalf("query: %v", err)
	}

	parseEvent := f.waitForEvent(t, tracer.EventParse, 3*time.Second)
	_, query := tracer.ExtractQuery(parseEvent.Buf[:parseEvent.Len])
	if query != "SELECT $1::text" {
		t.Errorf("captured query = %q, want %q", query, "SELECT $1::text")
	}

	bindEvent := f.waitForEvent(t, tracer.EventBind, 3*time.Second)
	params, err := tracer.ParseBindParams(bindEvent.Buf[:bindEvent.Len])
	if err != nil {
		t.Fatalf("parsing bind params: %v", err)
	}
	if len(params) != 1 || params[0] != "hello" {
		t.Errorf("params = %v, want [hello]", params)
	}
}

func TestE2ECreateInsertSelect(t *testing.T) {
	f := setupE2E(t)
	defer f.close()

	ctx := context.Background()
	_, err := f.conn.Exec(ctx, "CREATE TABLE IF NOT EXISTS e2e_test (id int, name text)", pgx.QueryExecModeSimpleProtocol)
	if err != nil {
		t.Fatalf("create table: %v", err)
	}
	defer f.conn.Exec(ctx, "DROP TABLE IF EXISTS e2e_test", pgx.QueryExecModeSimpleProtocol)

	event := f.waitForEvent(t, tracer.EventQuery, 3*time.Second)
	sql := tracer.TrimNull(event.Buf[:event.Len])
	if sql != "CREATE TABLE IF NOT EXISTS e2e_test (id int, name text)" {
		t.Errorf("captured CREATE = %q", sql)
	}

	f.drain()

	_, err = f.conn.Exec(ctx, "INSERT INTO e2e_test (id, name) VALUES ($1, $2)", pgx.QueryExecModeSimpleProtocol, 1, "world")
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	insertEvent := f.waitForEvent(t, tracer.EventQuery, 3*time.Second)
	insertSQL := tracer.TrimNull(insertEvent.Buf[:insertEvent.Len])
	if insertSQL != "INSERT INTO e2e_test (id, name) VALUES ( '1' ,  'world' )" {
		t.Errorf("captured INSERT = %q", insertSQL)
	}
}
