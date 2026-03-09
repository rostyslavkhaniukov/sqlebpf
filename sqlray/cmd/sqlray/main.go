package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"sqlray/internal/tracer"
)

type pidList []uint32

func (p *pidList) String() string { return fmt.Sprint(*p) }
func (p *pidList) Set(val string) error {
	for s := range strings.SplitSeq(val, ",") {
		s = strings.TrimSpace(s)
		n, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			return fmt.Errorf("invalid PID %q: %w", s, err)
		}
		*p = append(*p, uint32(n))
	}
	return nil
}

func main() {
	var pids pidList
	flag.Var(&pids, "pid", "PID(s) to trace (comma-separated, can be repeated)")
	flag.Parse()

	if flag.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "unexpected arguments: %v\n", flag.Args())
		flag.Usage()
		os.Exit(1)
	}

	opts := tracer.Options{
		FilterPIDs: pids,
	}
	if err := tracer.Run(opts); err != nil {
		log.Fatal(err)
	}
}
