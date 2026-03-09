VM_SSH  := ssh orb@orb
VM_CMD   = $(VM_SSH) 'cd $(CURDIR) && $(1)'

all: sqlray

generate-bpf:
	docker build -f Dockerfile.bpf -t sqlray-bpf-build .
	docker run --rm sqlray-bpf-build cat /sqlray-ebpf > sqlray/internal/tracer/sqlray-ebpf.o

sqlray: generate-bpf
	cd sqlray && CGO_ENABLED=0 go build -o ../sqlray ./cmd/sqlray

test:
	cd sqlray && go test -v -count 1 ./...

integration-test: generate-bpf
	docker build -f sqlray/tests/Dockerfile.test -t sqlray-test .
	docker run --rm --privileged sqlray-test

bpf-test:
	cd sqlray && sudo go test -v -tags integration -run TestBPF -count 1 ./tests/

e2e-test: generate-bpf
	docker build -f sqlray/tests/Dockerfile.e2e -t sqlray-e2e .
	docker run --rm --privileged sqlray-e2e

vm-%:
	$(call VM_CMD,sudo mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null; make $*)

clean:
	rm -f sqlray
	rm -f sqlray/internal/tracer/sqlray-ebpf.o

.PHONY: all clean generate-bpf test integration-test bpf-test e2e-test
