package tracer

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type Options struct {
	// FilterPIDs limits tracing to these process IDs.
	// Empty means trace all processes.
	FilterPIDs []uint32
}

func Run(opts Options) error {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock rlimit: %w", err)
	}

	objs, links, rd, err := LoadBPF()
	if err != nil {
		return fmt.Errorf("setting up BPF: %w", err)
	}
	defer objs.Close()
	defer CloseLinks(links)
	defer rd.Close()

	if err := configurePIDFilter(&objs, opts.FilterPIDs); err != nil {
		return fmt.Errorf("configuring PID filter: %w", err)
	}

	if len(opts.FilterPIDs) > 0 {
		fmt.Printf("Tracing SQL queries for PIDs %v... Ctrl+C to stop\n", opts.FilterPIDs)
	} else {
		fmt.Println("Tracing SQL queries (all processes)... Ctrl+C to stop")
	}

	go func() {
		<-stopper
		rd.Close()
	}()

	readEvents(rd)
	return nil
}

func configurePIDFilter(objs *BPFObjects, pids []uint32) error {
	if len(pids) == 0 {
		return nil
	}

	// Enable the filter: CONFIG[0] = 1
	key := uint32(0)
	val := uint32(1)
	if err := objs.Config.Put(key, val); err != nil {
		return fmt.Errorf("enabling PID filter: %w", err)
	}

	// Insert each target PID
	marker := uint8(1)
	for _, pid := range pids {
		if err := objs.TargetPids.Put(pid, marker); err != nil {
			return fmt.Errorf("adding PID %d: %w", pid, err)
		}
	}

	return nil
}

// AddPID inserts a PID into the filter at runtime.
// The filter must already be enabled via Options.FilterPIDs.
func AddPID(objs *BPFObjects, pid uint32) error {
	return objs.TargetPids.Put(pid, uint8(1))
}

// RemovePID removes a PID from the filter at runtime.
func RemovePID(objs *BPFObjects, pid uint32) error {
	return objs.TargetPids.Delete(pid)
}

func readEvents(rd *ringbuf.Reader) {
	var rec ringbuf.Record
	for {
		if err := rd.ReadInto(&rec); err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from ringbuf: %v", err)
			continue
		}

		event, err := DecodeEvent(rec.RawSample)
		if err != nil {
			log.Printf("%v", err)
			continue
		}

		HandleEvent(event)
	}
}
