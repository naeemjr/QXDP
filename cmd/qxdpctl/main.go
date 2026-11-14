package main

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/cilium/ebpf"
	qebpf "qxdp/internal/ebpf"
	"qxdp/internal/engine"
	"qxdp/internal/pcap"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, `qxdpctl — QXDP control plane

Usage: qxdpctl <command> [options]

Commands:
  status     Inspect attached XDP programs and kernel telemetry
  audit      Enumerate BPF programs and check for unauthorized hooks
  simulate   Run Red-vs-Blue live kernel simulation (BPF_PROG_TEST_RUN)
  replay     Generate and replay blind-spot verification trace
  tap        Read diagnostic tap ringbuf (stub)
`)
		os.Exit(1)
	}

	switch os.Args[1] {
	case "status":
		cmdStatus()
	case "audit":
		cmdAudit()
	case "simulate":
		cmdSimulate()
	case "replay":
		cmdReplay()
	case "tap":
		cmdTap()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}

func cmdStatus() {
	iface := "lo"
	for i, arg := range os.Args[2:] {
		if arg == "--iface" && i+3 < len(os.Args) {
			iface = os.Args[i+3]
		}
	}

	info, err := engine.InspectInterface(iface)
	if err != nil {
		fmt.Printf("  Interface %s: not found or no XDP attached\n", iface)
	} else {
		fmt.Printf("  Interface: %s\n", info.Ifname)
		fmt.Printf("  XDP ProgID: %d\n", info.ProgID)
		fmt.Printf("  Prog Tag:   %s\n", info.ProgTag)
	}

	fmt.Printf("  CPUs:       %d\n", runtime.NumCPU())
	fmt.Printf("  Kernel:     %s\n", getKernelVersion())
}

func cmdAudit() {
	fmt.Println("=== QXDP Detection Engineering Audit ===")
	fmt.Println()

	iface := "lo"
	for i, arg := range os.Args[2:] {
		if arg == "--iface" && i+3 < len(os.Args) {
			iface = os.Args[i+3]
		}
	}

	info, err := engine.InspectInterface(iface)
	if err != nil {
		fmt.Printf("[WARN] Interface %s: %v\n", iface, err)
	} else {
		fmt.Printf("[OK] Interface %s — ProgID=%d Tag=%s\n", info.Ifname, info.ProgID, info.ProgTag)
	}

	// enumerate loaded BPF programs
	fmt.Println("\nLoaded BPF programs:")
	var id ebpf.ProgramID
	count := 0
	for id, err = ebpf.ProgramGetNextID(0); err == nil; id, err = ebpf.ProgramGetNextID(id) {
		prog, perr := ebpf.NewProgramFromID(id)
		if perr != nil {
			continue
		}
		pInfo, ierr := prog.Info()
		prog.Close()
		if ierr != nil {
			continue
		}
		fmt.Printf("  ID=%d Type=%s Name=%s Tag=%s\n",
			id, pInfo.Type, pInfo.Name, pInfo.Tag)
		count++
	}
	fmt.Printf("\nTotal: %d BPF programs loaded\n", count)

	// verify our template loads
	spec, err := qebpf.LoadAegis()
	if err != nil {
		fmt.Printf("[FAIL] Cannot load qxdp_aegis template: %v\n", err)
		return
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if err != nil {
		fmt.Printf("[FAIL] Cannot verify qxdp_aegis: %v\n", err)
		return
	}
	progInfo, _ := coll.Programs["qxdp_aegis"].Info()
	fmt.Printf("\n[OK] qxdp_aegis template verified — Tag=%s\n", progInfo.Tag)
	coll.Close()

	fmt.Println("\n=== Audit complete ===")
}

func cmdSimulate() {
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║       QXDP Red-vs-Blue Live Kernel Simulation              ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	spec, err := qebpf.LoadAegis()
	if err != nil {
		fmt.Fprintf(os.Stderr, "LoadAegis: %v\n", err)
		os.Exit(1)
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "NewCollection: %v\n", err)
		os.Exit(1)
	}
	defer coll.Close()

	prog := coll.Programs["qxdp_aegis"]
	sketchMap := coll.Maps["sketch_map"]

	// init sketch
	ncpu := runtime.NumCPU()
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	var initState engine.SketchState
	for i := 0; i < 256; i++ {
		initState.PrngRing[i] = rng.Uint32()
	}
	perCPUInit := make([]engine.SketchState, ncpu)
	for i := range perCPUInit {
		perCPUInit[i] = initState
	}
	key := uint32(0)
	if err := sketchMap.Put(key, perCPUInit); err != nil {
		fmt.Fprintf(os.Stderr, "init sketch: %v\n", err)
		os.Exit(1)
	}

	dstIP := net.IPv4(192, 168, 1, 1)
	basePayload := make([]byte, 56)
	for i := range basePayload {
		basePayload[i] = byte(0xAA + i%16)
	}

	// Phase 1: inject traffic
	fmt.Println("[1/4] Injecting traffic via BPF_PROG_TEST_RUN...")

	benignPkts := make([][]byte, 1000)
	benignTokens := make([]uint64, 1000)
	for i := range benignPkts {
		pl := make([]byte, 56)
		rng.Read(pl)
		bSrc := net.IPv4(byte(172+rng.Intn(16)), byte(rng.Intn(256)), byte(rng.Intn(256)), byte(1+rng.Intn(254)))
		benignPkts[i] = buildSimPacket(bSrc, dstIP, uint16(10000+i), 80, pl, uint16(8000+rng.Intn(50000)), 0x10)
		benignTokens[i] = quantizeSimPacket(benignPkts[i])
	}

	floodPkts := make([][]byte, 5000)
	for i := range floodPkts {
		pl := make([]byte, 56)
		copy(pl, basePayload)
		mutBytes := int(0.25 * 56) // 25% mutation
		for j := 0; j < mutBytes; j++ {
			pl[j] = byte(rng.Intn(256))
		}
		// checksum-neutral perturbation on 20% of flood
		if i%5 == 0 {
			delta := uint16(rng.Intn(255) + 1)
			w0 := uint16(pl[8])<<8 | uint16(pl[9])
			w1 := uint16(pl[10])<<8 | uint16(pl[11])
			w0 += delta
			w1 -= delta
			pl[8], pl[9] = byte(w0>>8), byte(w0)
			pl[10], pl[11] = byte(w1>>8), byte(w1)
		}
		fSrc := net.IPv4(10, byte(rng.Intn(256)), byte(rng.Intn(256)), byte(1+rng.Intn(254)))
		floodPkts[i] = buildSimPacket(fSrc, dstIP, uint16(40000+i%10000), 80, pl, 29200, 0x10)
	}

	for _, pkt := range benignPkts {
		prog.Test(pkt)
	}
	for _, pkt := range floodPkts {
		prog.Test(pkt)
	}

	fmt.Printf("       Injected: %d benign + %d QXDP-Phantom attack packets\n", len(benignPkts), len(floodPkts))

	// Phase 2: extract signature
	fmt.Println("\n[2/4] Extracting signature from Siamese sketch...")

	t0 := time.Now()
	perCPURead := make([]engine.SketchState, ncpu)
	sketchMap.Lookup(key, &perCPURead)
	agg := engine.AggregateSketchStates(perCPURead)
	readTime := time.Since(t0)

	t1 := time.Now()
	sig := engine.AnalyzeAndExtractSignatureWithBaseline(agg, benignTokens)
	extractTime := time.Since(t1)

	fmt.Printf("       Centroid:  0x%016X\n", sig.Centroid)
	fmt.Printf("       CareMask:  0x%016X\n", sig.CareMask)
	fmt.Printf("       Theta:     %d\n", sig.HammingMax)
	fmt.Printf("       Gamma (Γ): %.3f\n", sig.Divergence)
	fmt.Printf("       Mode:      %s\n", sig.Mode)
	fmt.Printf("       H(src):    %.3f  H(A): %.3f  H(B): %.3f\n", sig.SrcH, sig.ViewAH, sig.ViewBH)

	if sig.CareMask == 0 {
		sig.CareMask = 0xFFFF000000000000
		sig.HammingMax = 4
	}

	// Phase 3: specialize + load
	fmt.Println("\n[3/4] Constant rewrite + kernel verifier load...")

	t2 := time.Now()
	sp, err := engine.CompileSpecializedProgram(spec, sig)
	specializeTime := time.Since(t2)
	if err != nil {
		fmt.Fprintf(os.Stderr, "specialize failed: %v\n", err)
		os.Exit(1)
	}
	defer sp.Close()

	fmt.Printf("       Verifier load:    %v\n", specializeTime)

	// Phase 4: evaluate
	fmt.Println("\n[4/4] Re-running traffic through specialized program...")

	var floodDrops, benignDrops int
	for _, pkt := range floodPkts {
		ret, _, _ := sp.Program.Test(pkt)
		if ret == 1 {
			floodDrops++
		}
	}
	for _, pkt := range benignPkts {
		ret, _, _ := sp.Program.Test(pkt)
		if ret == 1 {
			benignDrops++
		}
	}

	dropRate := float64(floodDrops) / float64(len(floodPkts)) * 100
	fpRate := float64(benignDrops) / float64(len(benignPkts)) * 100

	tp := float64(floodDrops)
	fp := float64(benignDrops)
	fn := float64(len(floodPkts) - floodDrops)
	precision := tp / (tp + fp + 1e-9)
	recall := tp / (tp + fn + 1e-9)
	f1 := 2 * precision * recall / (precision + recall + 1e-9)

	// measure throughput
	benchPkt := buildSimPacket(net.IPv4(10, 0, 0, 1), net.IPv4(192, 168, 1, 1), 12345, 80, basePayload, 29200, 0x10)
	_, benchTotal, _ := sp.Program.Benchmark(benchPkt, 500000, nil)
	benchNs := float64(time.Duration(500000) * time.Nanosecond)
	if benchTotal > 0 {
		benchNs = float64(benchTotal.Nanoseconds()) / 500000.0
	}
	// use wall clock as fallback
	wStart := time.Now()
	sp.Program.Benchmark(benchPkt, 500000, nil)
	wallNs := float64(time.Since(wStart).Nanoseconds()) / 500000.0

	fmt.Println()
	fmt.Println("┌─────────────────────────────────────────────────────┐")
	fmt.Println("│               SIMULATION RESULTS                    │")
	fmt.Println("├─────────────────────────────────────────────────────┤")
	fmt.Printf("│ Attack Drop Rate:     %6.1f%%                       │\n", dropRate)
	fmt.Printf("│ Benign False Positive: %5.1f%%                       │\n", fpRate)
	fmt.Printf("│ F1 Score:             %6.4f                       │\n", f1)
	fmt.Println("├─────────────────────────────────────────────────────┤")
	fmt.Println("│ Time-to-Mitigate Breakdown                         │")
	fmt.Printf("│   Sketch Read+Agg:    %12v                 │\n", readTime)
	fmt.Printf("│   Entropy Extract:    %12v                 │\n", extractTime)
	fmt.Printf("│   Verifier Load:      %12v                 │\n", specializeTime)
	fmt.Printf("│   Total TTM:          %12v                 │\n", readTime+extractTime+specializeTime)
	fmt.Println("├─────────────────────────────────────────────────────┤")
	fmt.Printf("│ Fast-Path Throughput:  %.1f ns/pkt (%.2f Mpps)     │\n", wallNs, 1000.0/wallNs)
	fmt.Println("└─────────────────────────────────────────────────────┘")

	_ = benchNs
}

func cmdReplay() {
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║       QXDP Blind-Spot Verification Replay                  ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	pcapPath := "/tmp/qxdp_blindspot.pcap"
	for i, arg := range os.Args[2:] {
		if arg == "--pcap" && i+3 < len(os.Args) {
			pcapPath = os.Args[i+3]
		}
	}

	fmt.Printf("[1/3] Generating blind-spot trace → %s\n", pcapPath)
	if err := pcap.GenerateBlindSpotTrace(pcapPath); err != nil {
		fmt.Fprintf(os.Stderr, "generate trace: %v\n", err)
		os.Exit(1)
	}

	frames, err := pcap.ReadPcap(pcapPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read pcap: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("       %d frames generated\n", len(frames))

	fmt.Println("\n[2/3] Replaying through BPF_PROG_TEST_RUN...")

	spec, err := qebpf.LoadAegis()
	if err != nil {
		fmt.Fprintf(os.Stderr, "LoadAegis: %v\n", err)
		os.Exit(1)
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "NewCollection: %v\n", err)
		os.Exit(1)
	}
	defer coll.Close()

	prog := coll.Programs["qxdp_aegis"]
	sketchMap := coll.Maps["sketch_map"]

	ncpu := runtime.NumCPU()
	rng := rand.New(rand.NewSource(42))
	var initState engine.SketchState
	for i := 0; i < 256; i++ {
		initState.PrngRing[i] = rng.Uint32()
	}
	perCPUInit := make([]engine.SketchState, ncpu)
	for i := range perCPUInit {
		perCPUInit[i] = initState
	}
	key := uint32(0)
	if err := sketchMap.Put(key, perCPUInit); err != nil {
		fmt.Fprintf(os.Stderr, "init sketch: %v\n", err)
		os.Exit(1)
	}

	var passed, processed int
	for _, fr := range frames {
		if len(fr.Data) < 34 {
			continue
		}
		ret, _, err := prog.Test(fr.Data)
		if err != nil {
			continue
		}
		processed++
		if ret == 2 {
			passed++
		}
	}

	fmt.Printf("       Processed: %d frames, %d passed XDP_PASS\n", processed, passed)

	fmt.Println("\n[3/3] Token distribution:")
	var benignTokens, synTokens, shiftTokens, encTokens, vlanTokens int
	for i, fr := range frames {
		q := quantizeSimPacket(fr.Data)
		if i < 100 {
			if q != 0 {
				benignTokens++
			}
		} else if i < 300 {
			if q != 0 {
				synTokens++
			}
		} else if i < 500 {
			if q != 0 {
				shiftTokens++
			}
		} else if i < 700 {
			if q != 0 {
				encTokens++
			}
		} else {
			if q != 0 {
				vlanTokens++
			}
		}
	}

	fmt.Printf("       Benign quantized:   %d/100\n", benignTokens)
	fmt.Printf("       SYN flood quantized: %d/200 (header-only, Mode C)\n", synTokens)
	fmt.Printf("       Shifted UDP:        %d/200 (shingle-invariant, Mode B)\n", shiftTokens)
	fmt.Printf("       Encrypted UDP:      %d/200 (random payload, Mode C)\n", encTokens)
	fmt.Printf("       VLAN TCP:           %d/100 (tag-stripped, Mode A)\n", vlanTokens)

	fmt.Println()
	fmt.Println("Replay complete. PCAP saved at:", pcapPath)
}

func cmdTap() {
	fmt.Println("qxdp tap: reading ringbuf — requires active XDP attachment")
	fmt.Println("Use: qxdpctl simulate (for self-contained kernel demo)")
}

func getKernelVersion() string {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return "unknown"
	}
	s := string(data)
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

// packet builders for simulate (mirror test helpers)

func buildSimPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte, window uint16, flags uint8) []byte {
	totalLen := 14 + 20 + 20 + len(payload)
	pkt := make([]byte, totalLen)
	pkt[12] = 0x08
	pkt[13] = 0x00
	pkt[14] = 0x45
	binary.BigEndian.PutUint16(pkt[16:18], uint16(20+20+len(payload)))
	pkt[22] = 64
	pkt[23] = 6
	copy(pkt[26:30], srcIP.To4())
	copy(pkt[30:34], dstIP.To4())

	ipHdr := pkt[14:34]
	binary.BigEndian.PutUint16(ipHdr[10:12], 0)
	binary.BigEndian.PutUint16(ipHdr[10:12], simIPChecksum(ipHdr))

	tcp := pkt[34:]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], 1000)
	binary.BigEndian.PutUint32(tcp[8:12], 0)
	tcp[12] = 0x50
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], window)
	copy(tcp[20:], payload)
	binary.BigEndian.PutUint16(tcp[16:18], 0)
	binary.BigEndian.PutUint16(tcp[16:18], simTCPChecksum(pkt[26:30], pkt[30:34], tcp[:20+len(payload)]))
	return pkt
}

func simIPChecksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	return ^uint16(sum)
}

func simTCPChecksum(srcIP, dstIP, tcpSeg []byte) uint16 {
	var sum uint32
	sum += uint32(binary.BigEndian.Uint16(srcIP[0:2]))
	sum += uint32(binary.BigEndian.Uint16(srcIP[2:4]))
	sum += uint32(binary.BigEndian.Uint16(dstIP[0:2]))
	sum += uint32(binary.BigEndian.Uint16(dstIP[2:4]))
	sum += 6
	sum += uint32(len(tcpSeg))
	for i := 0; i+1 < len(tcpSeg); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcpSeg[i : i+2]))
	}
	if len(tcpSeg)%2 == 1 {
		sum += uint32(tcpSeg[len(tcpSeg)-1]) << 8
	}
	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	return ^uint16(sum)
}

// quantizeSimPacket mirrors the BPF quantize_packet (Phase 4: two-stage with VLAN, IHL, anchor + shingle bloom)
func quantizeSimPacket(pkt []byte) uint64 {
	if len(pkt) < 14 {
		return 0
	}
	var keyEpoch uint64 = 0x9E3779B97F4A7C15

	// L2: parse ethernet + optional VLAN
	ethProto := binary.BigEndian.Uint16(pkt[12:14])
	l3 := 14
	for v := 0; v < 2; v++ {
		if ethProto == 0x8100 || ethProto == 0x88A8 {
			if l3+4 > len(pkt) {
				return 0
			}
			ethProto = binary.BigEndian.Uint16(pkt[l3+2 : l3+4])
			l3 += 4
		}
	}
	if ethProto != 0x0800 {
		return 0
	}

	// L3: IPv4 with dynamic IHL
	if l3+20 > len(pkt) {
		return 0
	}
	ihl := pkt[l3] & 0xF
	if ihl < 5 {
		return 0
	}
	ihlBytes := int(ihl) * 4
	if ihlBytes > 60 {
		ihlBytes = 60
	}
	if l3+ihlBytes > len(pkt) {
		return 0
	}

	proto := pkt[l3+9]
	ttl := pkt[l3+8]
	fragOff := binary.BigEndian.Uint16(pkt[l3+6 : l3+8])
	ipTotalLen := binary.BigEndian.Uint16(pkt[l3+2 : l3+4])

	l4 := l3 + ihlBytes
	var q uint64
	var l4PayloadLen uint32
	var l4HdrLen int

	switch proto {
	case 6: // TCP
		if l4+20 > len(pkt) {
			return 0
		}
		win := binary.BigEndian.Uint16(pkt[l4+14 : l4+16])
		var logWin uint8
		if win > 0 {
			for i := uint(0); i < 16; i++ {
				if win>>i != 0 {
					logWin = uint8(i)
				}
			}
		}
		q |= uint64(logWin&0xF) << 60

		rawFlagsDoff := binary.BigEndian.Uint16(pkt[l4+12 : l4+14])
		flags := rawFlagsDoff & 0x3F
		syn := (flags >> 1) & 1
		rst := (flags >> 2) & 1
		ack := (flags >> 4) & 1
		fin := flags & 1
		nib := uint8((rst << 3) | (syn << 2) | (ack << 1) | fin)
		q |= uint64(nib&0xF) << 52

		doff := (rawFlagsDoff >> 12) & 0xF
		l4HdrLen = int(doff) * 4
		if l4HdrLen < 20 {
			l4HdrLen = 20
		}
		if l4HdrLen > 60 {
			l4HdrLen = 60
		}

		hdrTotal := uint32(ihlBytes) + uint32(l4HdrLen)
		if uint32(ipTotalLen) > hdrTotal {
			l4PayloadLen = uint32(ipTotalLen) - hdrTotal
		}

	case 17: // UDP
		if l4+8 > len(pkt) {
			return 0
		}
		ulen := binary.BigEndian.Uint16(pkt[l4+4 : l4+6])
		var bucket uint8
		switch {
		case ulen >= 1024:
			bucket = 15
		case ulen >= 512:
			bucket = 12
		case ulen >= 256:
			bucket = 9
		case ulen >= 128:
			bucket = 6
		case ulen >= 64:
			bucket = 3
		default:
			bucket = 1
		}
		q |= uint64(bucket&0xF) << 60
		q |= uint64(1) << 52
		l4HdrLen = 8
		if ulen > 8 {
			l4PayloadLen = uint32(ulen) - 8
		}

	case 1: // ICMP
		if l4+8 > len(pkt) {
			return 0
		}
		q |= uint64(2) << 52
		l4HdrLen = 8

	default:
		return 0
	}

	// Nibble 2: TTL + frag
	ttlQ := (ttl & 0x3F) >> 2
	df := uint8((fragOff >> 14) & 1)
	mf := uint8((fragOff >> 13) & 1)
	nib1 := (ttlQ & 0xC) | (df << 1) | mf
	q |= uint64(nib1&0xF) << 56

	// Nibble 0: payload length bucket (/32)
	plBucket := l4PayloadLen / 32
	if plBucket > 15 {
		plBucket = 15
	}
	q |= uint64(plBucket&0xF) << 48

	// Stage 2: lower 48-bit payload quantizer
	payloadStart := l4 + l4HdrLen
	if payloadStart+48 <= len(pkt) {
		pl := pkt[payloadStart:]

		// Anchor: bits 32..47
		w0 := uint64(pl[0])<<56 | uint64(pl[1])<<48 | uint64(pl[2])<<40 | uint64(pl[3])<<32 |
			uint64(pl[4])<<24 | uint64(pl[5])<<16 | uint64(pl[6])<<8 | uint64(pl[7])
		w1 := uint64(pl[8])<<56 | uint64(pl[9])<<48 | uint64(pl[10])<<40 | uint64(pl[11])<<32 |
			uint64(pl[12])<<24 | uint64(pl[13])<<16 | uint64(pl[14])<<8 | uint64(pl[15])
		ah := simFasthash64(w0, keyEpoch) ^ simFasthash64(w1, keyEpoch+1)
		q |= (ah & 0xFFFF) << 32

		// Shingle bloom: bits 0..31
		var sbl uint32
		for i := 0; i < 16; i++ {
			off := 8 + i*2
			w := uint32(pl[off])<<24 | uint32(pl[off+1])<<16 | uint32(pl[off+2])<<8 | uint32(pl[off+3])
			h := (w ^ uint32(keyEpoch)) * 0x9E3779B1
			h ^= h >> 16
			sbl |= 1 << ((h >> 27) & 31)
		}
		q |= uint64(sbl)
	}

	return q
}

func simFasthash64(val, seed uint64) uint64 {
	var m uint64 = 0x880355F21E6D1965
	mix := func(h uint64) uint64 {
		h ^= h >> 23
		h *= 0x2127599BF4325C37
		h ^= h >> 47
		return h
	}
	h := seed ^ (8 * m)
	h ^= mix(val)
	h *= m
	return mix(h)
}
