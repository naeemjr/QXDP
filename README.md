# QXDP: Quantized eXpress Data Path

**Sub-byte packet fragment quantization and runtime bytecode synthesis for line-rate polymorphic DDoS mitigation.**

**Preprint:** [ResearchGate](https://www.researchgate.net/publication/417651816_QXDP_Sub-Byte_Packet_Quantization_and_Runtime_Bytecode_Synthesis_for_Line-Rate_Polymorphic_DDoS_Mitigation)

QXDP is a complete eBPF/XDP system that compresses packet headers and payload fragments into 64-bit quantized tokens, tracks their frequency distribution in a dual-view sketch data structure, and synthesizes specialized XDP programs at runtime to drop polymorphic attack traffic at line rate with zero map lookups on the fast path.

---

## Architecture

QXDP consists of two adversarial subsystems designed for co-evaluation:

### QXDP-Aegis (Blue Team Defense)

The defense pipeline operates in a closed loop:

```
Ingress Packet
    |
    v
[XDP Hook] --> quantize_packet(p, K) --> 64-bit token Q_K(p)
    |
    |--- Fast Path: SWAR popcount Hamming distance against
    |    constant-folded centroid. Match --> XDP_DROP (0 map lookups)
    |
    v
[Siamese HeavyKeeper Sketch]
    |-- View A: INT4 structural header counters (window bucket, TTL residual, flags, length)
    |-- View B: Keyed HeavyKeeper payload fingerprint tracking with exponential decay
    |
    v
[Userspace Control Plane]
    |-- Per-CPU sketch read + aggregation
    |-- Shannon entropy divergence (Gamma = H(src) / min(H(A), H(B)))
    |-- Centroid extraction + care mask calibration (95% invariance, benign baseline exclusion)
    |-- Constant rewrite via cilium/ebpf spec.Variables[].Set()
    |-- Kernel verifier load + atomic BPF_LINK_UPDATE swap
```

### QXDP-Phantom (Red Team Mutator)

A polymorphic stress-test mutator that generates checksum-neutral evasion traffic:

- Per-packet TTL rotation and TCP window jitter driven by a per-CPU counter
- Ones-complement complementary nibble perturbation: modifies adjacent 16-bit payload words by +delta/-delta, preserving TCP/UDP checksums while altering payload fingerprints
- Configurable mutation rates (0%--50% of payload bytes) for systematic ROC evaluation

---

## Mathematical Formulation

### 64-Bit Packet Quantization

Each packet is compressed into a single 64-bit token:

```
Q_K(p) = [ n_0 | n_1 | n_2 | n_3 | LSH_K(payload, 48) ]
           4b    4b    4b    4b         48 bits
```

| Nibble | Bits    | Content                                      |
|--------|---------|----------------------------------------------|
| n_0    | 63--60  | log2(TCP window) or UDP length bucket         |
| n_1    | 59--56  | TTL hop-distance residual + DF/MF frag flags  |
| n_2    | 55--52  | Transport state (SYN/RST/ACK/FIN for TCP)     |
| n_3    | 51--48  | L4 payload length bucket (floor(len/32))       |
| Anchor | 47--32  | Protocol header offset anchor (2 x fasthash64 XOR -> 16 bits) |
| Shingle| 31--0   | Shift-invariant sliding shingle bloom (16 x 4B at 2B stride) |

**Stage 1** (always): Produces the upper 16-bit header token from transport protocol fields. Handles VLAN stripping (up to 2 stacked 802.1Q/802.1ad tags), dynamic IHL, and works on any valid IPv4 TCP/UDP/ICMP packet, including 54-byte SYN floods with zero payload.

**Stage 2** (conditional, >= 48 payload bytes): The anchor captures the first 16 bytes of L4 payload through two keyed fasthash64 projections XOR'd to 16 bits. The shingle bloom hashes 16 overlapping 4-byte windows at 2-byte stride into a 32-bit bloom filter — content-addressed, not position-addressed, defeating 1-7 byte payload prepend evasion.

**Context-aware synthesis modes** select which token zones to enforce:
- **Mode A**: Full hybrid (header + anchor + shingle).
- **Mode B**: Anchor noisy from payload shift; enforce header + shingle only.
- **Mode C**: Encrypted/no-payload fallback; header-only with tight theta <= 1.

### Fast-Path Efficiency Bound

The constant-folded fast path evaluates the Hamming distance between a packet's token and the attack centroid using a 3-cycle SWAR popcount:

```
rho = popcount64((Q_K(p) XOR C) AND M)
```

Where `C` is the centroid, `M` is the care mask, and `rho < theta` triggers XDP_DROP. When `CFG_ENABLE_TAP = 0`, the entire drop path executes with **zero BPF map lookups** -- the signature parameters are compiled directly into ALU register immediates via constant folding.

### SWAR Popcount (3 Cycles)

```c
x -= (x >> 1) & 0x5555555555555555ULL;
x  = (x & 0x3333333333333333ULL) + ((x >> 2) & 0x3333333333333333ULL);
x  = (x + (x >> 4)) & 0x0F0F0F0F0F0F0F0FULL;
return (x * 0x0101010101010101ULL) >> 56;
```

### Checksum-Neutral Perturbation

QXDP-Phantom modifies payload while preserving transport checksums:

```
w_0' = w_0 + delta   (ones-complement)
w_1' = w_1 - delta   (ones-complement)
```

Since TCP/UDP checksums are ones-complement sums, the net contribution of the word pair is unchanged.

---

## Quickstart

```bash
# Install dependencies and build
make deps && make build

# Run all 8 tests (requires root for BPF)
make test

# Run kernel-batch benchmarks
make bench

# Red-vs-Blue live kernel simulation (no external NIC needed)
sudo ./bin/qxdpctl simulate

# Blind-spot verification replay (generates + replays PCAP)
sudo ./bin/qxdpctl replay

# BPF program audit and enumeration
sudo ./bin/qxdpctl audit

# Live veth integration test
make integration
```

---

## Key Results

Measured on 13th Gen Intel Core i7-13700KF, Linux 6.18 (WSL2), per-CPU sketch struct = 19,504 bytes (L1-cache resident).

### Throughput (Kernel-Batch, BPF_PROG_TEST_RUN with Repeat)

| Path                  | ns/pkt | Mpps  |
|-----------------------|--------|-------|
| Fast-Path Drop        | 45.7   | 21.9  |
| Full Sketch Update    | 54.7   | 18.3  |

### Detection Accuracy (Polymorphic Mutation Sweep)

| Mutation Rate | Attack Drop (%) | Benign FP (%) |
|---------------|-----------------|---------------|
| 0%            | 100.0           | 0.0           |
| 10%           | 100.0           | 0.0           |
| 25%           | 100.0           | 0.0           |
| 40%           | 100.0           | 0.0           |
| 50%           | 100.0           | 0.6           |

### Time-to-Mitigate

| Phase                              | Duration   |
|-------------------------------------|-----------|
| Per-CPU Sketch Read + Aggregation   | 324.3 us  |
| Entropy and Centroid Extraction     | 3.2 us    |
| Constant Rewrite + Verifier Load   | 6,849 us  |
| **Total**                           | **7.18 ms** |

### Red-vs-Blue (QXDP-Aegis vs Baseline)

| Attack Scenario              | Baseline Drop% | Baseline FP% | Aegis Drop% | Aegis FP% |
|------------------------------|---------------|-------------|------------|----------|
| Volumetric Static            | 100.0         | 0.0         | 100.0      | 0.0      |
| Polymorphic 25%              | 100.0         | 0.0         | 100.0      | 0.0      |
| Polymorphic 40%              | 100.0         | 3.3         | 100.0      | 0.0      |
| Checksum-Neutral Pollution   | 100.0         | 0.3         | 100.0      | 0.0      |
| Window-Jitter + Padding      | 100.0         | 0.0         | 100.0      | 0.0      |

Against the full QXDP-Phantom adaptive attack (25% mutation + checksum-neutral perturbation + decoy noise): **F1 = 1.0**.

---

## Project Structure

```
qxdp/
├── bpf/
│   ├── headers/
│   │   └── qxdp_common.h            # Shared structs, quantizer, SWAR popcount, fasthash64
│   ├── qxdp_aegis.bpf.c             # Main XDP program (8 constant-folded signature slots)
│   ├── qxdp_morph_bench.bpf.c       # QXDP-Phantom polymorphic mutator
│   └── qxdp_map_baseline.bpf.c      # Map-lookup baseline for scaling comparison
├── internal/
│   ├── ebpf/
│   │   └── gen.go                    # bpf2go code generation directives
│   ├── engine/
│   │   ├── entropy.go                # Shannon entropy, sketch aggregation, signature extraction
│   │   ├── specializer.go            # Runtime constant folding and multi-signature compilation
│   │   └── auditor.go                # BPF program enumeration and interface inspection
│   └── pcap/
│       ├── tap.go                    # Pcap writer for diagnostic tap events
│       └── replay.go                 # Native pcap reader + blind-spot trace generator
├── bench/
│   └── qxdp_test.go                 # 8 tests + 2 benchmarks + paper table generation
├── cmd/
│   ├── qxdpd/
│   │   └── main.go                   # Daemon: attaches XDP, polls sketch, specializes
│   └── qxdpctl/
│       └── main.go                   # CLI: status, audit, simulate, replay, tap
├── paper/
│   └── qxdp_paper.tex               # Full LaTeX research paper
├── Makefile                          # deps, generate, build, test, bench, integration, clean
├── go.mod
├── RESULTS.md                        # Empirical evaluation tables
└── README.md
```

---

## Requirements

| Dependency       | Minimum Version | Notes                                  |
|------------------|-----------------|----------------------------------------|
| Linux kernel     | 5.15+           | BTF support required; 6.1+ recommended |
| clang/LLVM       | 14+             | BPF target backend                     |
| Go               | 1.21+           | Module support                         |
| libbpf-dev       | 1.0+            | BPF helper headers                     |
| bpftool          | 7.0+            | BTF and program inspection             |
| cilium/ebpf (Go) | 0.22.0          | Installed via `make deps`              |

Root privileges (or `CAP_BPF` + `CAP_NET_ADMIN`) are required for loading BPF programs and attaching XDP hooks.

---

## License

GPL-2.0 (BPF programs) / MIT (userspace Go code).
