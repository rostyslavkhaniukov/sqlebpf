package tracer

import (
	"bytes"
	_ "embed"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:embed sqlray-ebpf.o
var bpfObj []byte

type BPFObjects struct {
	EnterRecvfrom *ebpf.Program
	ExitRecvfrom  *ebpf.Program
	SqlEvents     *ebpf.Map
	ActiveReads   *ebpf.Map
	Config        *ebpf.Map
	TargetPids    *ebpf.Map
}

func (o *BPFObjects) Close() {
	for _, c := range []interface{ Close() error }{
		o.EnterRecvfrom, o.ExitRecvfrom,
		o.SqlEvents, o.ActiveReads,
		o.Config, o.TargetPids,
	} {
		if c != nil {
			c.Close()
		}
	}
}

func LoadBPF() (objs BPFObjects, links []link.Link, rd *ringbuf.Reader, err error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfObj))
	if err != nil {
		return objs, nil, nil, fmt.Errorf("loading BPF spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return objs, nil, nil, fmt.Errorf("creating BPF collection: %w", err)
	}

	objs.EnterRecvfrom = coll.Programs["trace_enter_recvfrom"]
	objs.ExitRecvfrom = coll.Programs["trace_exit_recvfrom"]
	objs.SqlEvents = coll.Maps["SQL_EVENTS"]
	objs.ActiveReads = coll.Maps["ACTIVE_READS"]
	objs.Config = coll.Maps["CONFIG"]
	objs.TargetPids = coll.Maps["TARGET_PIDS"]

	if objs.EnterRecvfrom == nil || objs.ExitRecvfrom == nil || objs.SqlEvents == nil ||
		objs.Config == nil || objs.TargetPids == nil {
		coll.Close()
		return objs, nil, nil, fmt.Errorf("missing expected BPF programs or maps")
	}

	// Detach from collection so Close() on coll doesn't close our refs
	coll.DetachProgram("trace_enter_recvfrom")
	coll.DetachProgram("trace_exit_recvfrom")
	coll.DetachMap("SQL_EVENTS")
	coll.DetachMap("ACTIVE_READS")
	coll.DetachMap("CONFIG")
	coll.DetachMap("TARGET_PIDS")
	coll.Close()

	links, err = attachLinks(&objs)
	if err != nil {
		objs.Close()
		return objs, nil, nil, err
	}

	rd, err = ringbuf.NewReader(objs.SqlEvents)
	if err != nil {
		CloseLinks(links)
		objs.Close()
		return objs, nil, nil, fmt.Errorf("opening ringbuf reader: %w", err)
	}

	return objs, links, rd, nil
}

func attachLinks(objs *BPFObjects) ([]link.Link, error) {
	var links []link.Link

	attach := func(group, name string, prog *ebpf.Program) error {
		l, err := link.Tracepoint(group, name, prog, nil)
		if err != nil {
			return fmt.Errorf("attaching %s/%s: %w", group, name, err)
		}
		links = append(links, l)
		return nil
	}

	if err := attach("syscalls", "sys_enter_recvfrom", objs.EnterRecvfrom); err != nil {
		CloseLinks(links)
		return nil, err
	}
	if err := attach("syscalls", "sys_exit_recvfrom", objs.ExitRecvfrom); err != nil {
		CloseLinks(links)
		return nil, err
	}

	return links, nil
}

func CloseLinks(links []link.Link) {
	for _, l := range links {
		l.Close()
	}
}
