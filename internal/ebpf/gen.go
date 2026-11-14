package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -I../../bpf -I/usr/include/x86_64-linux-gnu" -target amd64 Aegis ../../bpf/qxdp_aegis.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -I../../bpf -I/usr/include/x86_64-linux-gnu" -target amd64 Morph ../../bpf/qxdp_morph_bench.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -I../../bpf -I/usr/include/x86_64-linux-gnu" -target amd64 MapBaseline ../../bpf/qxdp_map_baseline.bpf.c
