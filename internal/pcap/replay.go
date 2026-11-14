package pcap

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
)

type PcapFrame struct {
	TsSec   uint32
	TsUsec  uint32
	CapLen  uint32
	OrigLen uint32
	Data    []byte
}

func ReadPcap(path string) ([]PcapFrame, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) < 24 {
		return nil, fmt.Errorf("pcap too short")
	}
	magic := binary.LittleEndian.Uint32(data[0:4])
	if magic != 0xA1B2C3D4 {
		return nil, fmt.Errorf("bad pcap magic: 0x%08X", magic)
	}

	var frames []PcapFrame
	off := 24
	for off+16 <= len(data) {
		tsSec := binary.LittleEndian.Uint32(data[off : off+4])
		tsUsec := binary.LittleEndian.Uint32(data[off+4 : off+8])
		capLen := binary.LittleEndian.Uint32(data[off+8 : off+12])
		origLen := binary.LittleEndian.Uint32(data[off+12 : off+16])
		off += 16
		if off+int(capLen) > len(data) {
			break
		}
		frame := PcapFrame{
			TsSec:   tsSec,
			TsUsec:  tsUsec,
			CapLen:  capLen,
			OrigLen: origLen,
			Data:    make([]byte, capLen),
		}
		copy(frame.Data, data[off:off+int(capLen)])
		off += int(capLen)
		frames = append(frames, frame)
	}
	return frames, nil
}

func WritePcapFrames(path string, frames []PcapFrame) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:4], 0xA1B2C3D4)
	binary.LittleEndian.PutUint16(hdr[4:6], 2)
	binary.LittleEndian.PutUint16(hdr[6:8], 4)
	binary.LittleEndian.PutUint32(hdr[16:20], 65535)
	binary.LittleEndian.PutUint32(hdr[20:24], 1) // LINKTYPE_ETHERNET
	if _, err := f.Write(hdr); err != nil {
		return err
	}

	for _, fr := range frames {
		rec := make([]byte, 16)
		binary.LittleEndian.PutUint32(rec[0:4], fr.TsSec)
		binary.LittleEndian.PutUint32(rec[4:8], fr.TsUsec)
		capLen := uint32(len(fr.Data))
		binary.LittleEndian.PutUint32(rec[8:12], capLen)
		binary.LittleEndian.PutUint32(rec[12:16], fr.OrigLen)
		if _, err := f.Write(rec); err != nil {
			return err
		}
		if _, err := f.Write(fr.Data); err != nil {
			return err
		}
	}
	return nil
}

func GenerateBlindSpotTrace(path string) error {
	rng := rand.New(rand.NewSource(42))
	var frames []PcapFrame
	ts := uint32(1000)

	add := func(pkt []byte) {
		frames = append(frames, PcapFrame{
			TsSec:   ts,
			TsUsec:  uint32(len(frames) * 1000),
			CapLen:  uint32(len(pkt)),
			OrigLen: uint32(len(pkt)),
			Data:    pkt,
		})
	}

	dstIP := net.IPv4(192, 168, 1, 1)

	// === Benign: HTTP, DNS, TLS, SSH ===
	for i := 0; i < 50; i++ {
		pl := make([]byte, 64)
		rng.Read(pl)
		src := net.IPv4(byte(172+rng.Intn(16)), byte(rng.Intn(256)), byte(rng.Intn(256)), byte(1+rng.Intn(254)))
		add(buildReplayTCP(src, dstIP, uint16(10000+i), 80, pl, uint16(8000+rng.Intn(50000)), 0x10, nil))
	}
	for i := 0; i < 20; i++ {
		pl := make([]byte, 48)
		rng.Read(pl)
		src := net.IPv4(byte(172+rng.Intn(16)), byte(rng.Intn(256)), byte(rng.Intn(256)), byte(1+rng.Intn(254)))
		add(buildReplayUDP(src, dstIP, uint16(30000+i), 53, pl))
	}
	for i := 0; i < 20; i++ {
		pl := make([]byte, 64)
		rng.Read(pl)
		src := net.IPv4(byte(172+rng.Intn(16)), byte(rng.Intn(256)), byte(rng.Intn(256)), byte(1+rng.Intn(254)))
		add(buildReplayTCP(src, dstIP, uint16(20000+i), 443, pl, uint16(8000+rng.Intn(50000)), 0x10, nil))
	}
	for i := 0; i < 10; i++ {
		pl := make([]byte, 64)
		rng.Read(pl)
		src := net.IPv4(byte(172+rng.Intn(16)), byte(rng.Intn(256)), byte(rng.Intn(256)), byte(1+rng.Intn(254)))
		add(buildReplayTCP(src, dstIP, uint16(50000+i), 22, pl, uint16(8000+rng.Intn(50000)), 0x10, nil))
	}

	// === Attack: SYN flood (54-64 bytes, no payload) ===
	for i := 0; i < 200; i++ {
		src := net.IPv4(10, byte(rng.Intn(256)), byte(rng.Intn(256)), byte(1+rng.Intn(254)))
		add(buildReplayTCP(src, dstIP, uint16(40000+i%10000), 80, nil, 29200, 0x02, nil))
	}

	// === Attack: shifted UDP flood (1-7 byte prepend) ===
	baseUDP := make([]byte, 56)
	for i := range baseUDP {
		baseUDP[i] = byte(0xDD + i%16)
	}
	for i := 0; i < 200; i++ {
		shift := 1 + rng.Intn(7)
		pl := make([]byte, shift+len(baseUDP))
		rng.Read(pl[:shift])
		copy(pl[shift:], baseUDP)
		src := net.IPv4(10, byte(rng.Intn(256)), byte(rng.Intn(256)), byte(1+rng.Intn(254)))
		add(buildReplayUDP(src, dstIP, uint16(50000+i%10000), 9999, pl))
	}

	// === Attack: encrypted/random UDP flood ===
	for i := 0; i < 200; i++ {
		pl := make([]byte, 64)
		rng.Read(pl)
		src := net.IPv4(10, byte(rng.Intn(256)), byte(rng.Intn(256)), byte(1+rng.Intn(254)))
		add(buildReplayUDP(src, dstIP, uint16(60000+i%10000), 4789, pl))
	}

	// === Attack: VLAN-tagged TCP flood ===
	for i := 0; i < 100; i++ {
		pl := make([]byte, 56)
		copy(pl, baseUDP)
		for j := 0; j < 14; j++ {
			pl[j] = byte(rng.Intn(256))
		}
		src := net.IPv4(10, byte(rng.Intn(256)), byte(rng.Intn(256)), byte(1+rng.Intn(254)))
		vlan := uint16(100 + rng.Intn(100))
		add(buildReplayTCP(src, dstIP, uint16(40000+i%10000), 80, pl, 29200, 0x10, &vlan))
	}

	return WritePcapFrames(path, frames)
}

func buildReplayTCP(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte, window uint16, flags uint8, vlanID *uint16) []byte {
	ethLen := 14
	if vlanID != nil {
		ethLen = 18
	}
	totalLen := ethLen + 20 + 20 + len(payload)
	pkt := make([]byte, totalLen)

	if vlanID != nil {
		pkt[12] = 0x81
		pkt[13] = 0x00
		binary.BigEndian.PutUint16(pkt[14:16], *vlanID)
		pkt[16] = 0x08
		pkt[17] = 0x00
	} else {
		pkt[12] = 0x08
		pkt[13] = 0x00
	}

	ipOff := ethLen
	pkt[ipOff] = 0x45
	binary.BigEndian.PutUint16(pkt[ipOff+2:ipOff+4], uint16(20+20+len(payload)))
	pkt[ipOff+8] = 64
	pkt[ipOff+9] = 6
	copy(pkt[ipOff+12:ipOff+16], srcIP.To4())
	copy(pkt[ipOff+16:ipOff+20], dstIP.To4())

	ipHdr := pkt[ipOff : ipOff+20]
	binary.BigEndian.PutUint16(ipHdr[10:12], 0)
	binary.BigEndian.PutUint16(ipHdr[10:12], replayIPChecksum(ipHdr))

	tcpOff := ipOff + 20
	tcp := pkt[tcpOff:]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], 1000)
	tcp[12] = 0x50
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], window)
	copy(tcp[20:], payload)
	binary.BigEndian.PutUint16(tcp[16:18], 0)
	binary.BigEndian.PutUint16(tcp[16:18], replayTCPChecksum(pkt[ipOff+12:ipOff+16], pkt[ipOff+16:ipOff+20], tcp[:20+len(payload)]))

	return pkt
}

func buildReplayUDP(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	totalLen := 14 + 20 + 8 + len(payload)
	pkt := make([]byte, totalLen)

	pkt[12] = 0x08
	pkt[13] = 0x00
	pkt[14] = 0x45
	binary.BigEndian.PutUint16(pkt[16:18], uint16(20+8+len(payload)))
	pkt[22] = 64
	pkt[23] = 17
	copy(pkt[26:30], srcIP.To4())
	copy(pkt[30:34], dstIP.To4())

	ipHdr := pkt[14:34]
	binary.BigEndian.PutUint16(ipHdr[10:12], 0)
	binary.BigEndian.PutUint16(ipHdr[10:12], replayIPChecksum(ipHdr))

	udp := pkt[34:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	copy(udp[8:], payload)

	return pkt
}

func replayIPChecksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	return ^uint16(sum)
}

func replayTCPChecksum(srcIP, dstIP, tcpSeg []byte) uint16 {
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
