package pcap

import (
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf/ringbuf"
)

type TapEvent struct {
	TimestampNS uint64
	QToken      uint64
	Action      uint32
	PktLen      uint32
	RawFrame    [128]byte
}

type TapReader struct {
	reader *ringbuf.Reader
}

func NewTapReader(rbMap *os.File) (*TapReader, error) {
	return &TapReader{}, nil
}

func WritePcap(path string, events []TapEvent) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create pcap: %w", err)
	}
	defer f.Close()

	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:4], 0xA1B2C3D4)
	binary.LittleEndian.PutUint16(hdr[4:6], 2)
	binary.LittleEndian.PutUint16(hdr[6:8], 4)
	binary.LittleEndian.PutUint32(hdr[8:12], 0)
	binary.LittleEndian.PutUint32(hdr[12:16], 0)
	binary.LittleEndian.PutUint32(hdr[16:20], 128)
	binary.LittleEndian.PutUint32(hdr[20:24], 1)
	if _, err := f.Write(hdr); err != nil {
		return err
	}

	for _, ev := range events {
		ts := time.Duration(ev.TimestampNS) * time.Nanosecond
		sec := uint32(ts.Seconds())
		usec := uint32((ts - time.Duration(sec)*time.Second).Microseconds())
		capLen := ev.PktLen
		if capLen > 128 {
			capLen = 128
		}

		rec := make([]byte, 16)
		binary.LittleEndian.PutUint32(rec[0:4], sec)
		binary.LittleEndian.PutUint32(rec[4:8], usec)
		binary.LittleEndian.PutUint32(rec[8:12], capLen)
		binary.LittleEndian.PutUint32(rec[12:16], ev.PktLen)
		if _, err := f.Write(rec); err != nil {
			return err
		}
		if _, err := f.Write(ev.RawFrame[:capLen]); err != nil {
			return err
		}
	}

	return nil
}
