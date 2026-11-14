SHELL := /bin/bash

.PHONY: deps generate build test bench integration clean all

all: deps generate build

deps:
	@echo "=== Checking dependencies ==="
	@which clang >/dev/null 2>&1 || (echo "ERROR: clang not found"; exit 1)
	@which llvm-strip >/dev/null 2>&1 || (echo "ERROR: llvm-strip not found"; exit 1)
	@which bpftool >/dev/null 2>&1 || (echo "ERROR: bpftool not found"; exit 1)
	@which go >/dev/null 2>&1 || (echo "ERROR: go not found"; exit 1)
	@echo "clang: $$(clang --version | head -1)"
	@echo "go: $$(go version)"
	@echo "bpftool: $$(bpftool version | head -1)"
	go get github.com/cilium/ebpf@latest
	go install github.com/cilium/ebpf/cmd/bpf2go@latest
	@echo "=== Dependencies OK ==="

generate:
	@echo "=== Generating eBPF Go bindings ==="
	go generate ./internal/ebpf/...
	@echo "=== Generate OK ==="

build: generate
	@echo "=== Building binaries ==="
	@mkdir -p bin
	go build -o bin/qxdpd ./cmd/qxdpd/
	go build -o bin/qxdpctl ./cmd/qxdpctl/
	@echo "=== Build OK ==="
	@ls -la bin/

test:
	@echo "=== Running tests ==="
	@if [ "$$(id -u)" != "0" ]; then \
		echo "(elevating with sudo for BPF access)"; \
		sudo -E $$(which go) test -v -count=1 ./bench/...; \
	else \
		go test -v -count=1 ./bench/...; \
	fi
	@echo "=== Tests OK ==="

integration:
	@echo "=== Running live veth integration test ==="
	@if [ "$$(id -u)" != "0" ]; then \
		echo "(elevating with sudo for BPF + netns access)"; \
		sudo -E $$(which go) test -v -count=1 -run='TestLiveVeth' ./bench/...; \
	else \
		go test -v -count=1 -run='TestLiveVeth' ./bench/...; \
	fi
	@echo "=== Integration OK ==="

bench:
	@echo "=== Running benchmarks ==="
	@if [ "$$(id -u)" != "0" ]; then \
		echo "(elevating with sudo for BPF access)"; \
		sudo -E $$(which go) test -v -run='^$$' -bench=. -benchmem -count=1 ./bench/...; \
	else \
		go test -v -run='^$$' -bench=. -benchmem -count=1 ./bench/...; \
	fi
	@echo "=== Bench OK ==="

clean:
	rm -f internal/ebpf/*_bpfel.go internal/ebpf/*_bpfeb.go internal/ebpf/*_bpfel.o internal/ebpf/*_bpfeb.o
	rm -f bin/qxdpd bin/qxdpctl
	@echo "=== Clean OK ==="
