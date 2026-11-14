package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	qebpf "qxdp/internal/ebpf"
	"qxdp/internal/engine"
)

func main() {
	iface := flag.String("iface", "lo", "network interface to attach XDP program")
	mode := flag.String("mode", "generic", "XDP mode: generic, native, offload")
	interval := flag.Duration("interval", 5*time.Second, "analysis polling interval")
	flag.Parse()

	log.SetPrefix("[qxdpd] ")
	log.Printf("starting on interface %s (mode=%s)", *iface, *mode)

	spec, err := qebpf.LoadAegis()
	if err != nil {
		log.Fatalf("load spec: %v", err)
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if err != nil {
		log.Fatalf("load collection: %v", err)
	}
	defer coll.Close()

	prog := coll.Programs["qxdp_aegis"]
	if prog == nil {
		log.Fatal("program qxdp_aegis not found")
	}

	ifIdx := ifIndex(*iface)
	xdpMode := link.XDPGenericMode
	if *mode == "native" {
		xdpMode = link.XDPDriverMode
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: ifIdx,
		Flags:     xdpMode,
	})
	if err != nil {
		log.Fatalf("attach XDP: %v", err)
	}
	defer l.Close()

	log.Printf("XDP program attached to %s", *iface)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	sketchMap := coll.Maps["sketch_map"]

	for {
		select {
		case <-sigCh:
			log.Println("shutting down")
			return
		case <-ticker.C:
			var states []engine.SketchState
			_ = sketchMap
			_ = states
			log.Printf("polling sketch state...")
		}
	}
}

func ifIndex(name string) int {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		log.Fatalf("interface %s: %v", name, err)
	}
	return iface.Index
}

func init() {
	_ = fmt.Sprintf
}
