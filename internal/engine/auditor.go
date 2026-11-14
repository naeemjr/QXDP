package engine

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf"
)

type InterfaceInfo struct {
	Ifname    string
	ProgID    uint32
	ProgTag   string
	InsnCount int
}

func InspectInterface(ifname string) (*InterfaceInfo, error) {
	_, err := findIfindex(ifname)
	if err != nil {
		return nil, err
	}

	info := &InterfaceInfo{Ifname: ifname}

	progID, err := findXDPProgID(ifname)
	if err == nil && progID != 0 {
		info.ProgID = progID
		prog, err := ebpf.NewProgramFromID(ebpf.ProgramID(progID))
		if err == nil {
			defer prog.Close()
			pInfo, err := prog.Info()
			if err == nil {
				info.ProgTag = pInfo.Tag
			}
		}
	}

	return info, nil
}

func findIfindex(ifname string) (int, error) {
	path := fmt.Sprintf("/sys/class/net/%s/ifindex", ifname)
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("interface %s not found: %w", ifname, err)
	}
	var idx int
	fmt.Sscanf(string(data), "%d", &idx)
	return idx, nil
}

func findXDPProgID(ifname string) (uint32, error) {
	var id ebpf.ProgramID
	var err error
	for id, err = ebpf.ProgramGetNextID(0); err == nil; id, err = ebpf.ProgramGetNextID(id) {
		prog, perr := ebpf.NewProgramFromID(id)
		if perr != nil {
			continue
		}
		info, ierr := prog.Info()
		prog.Close()
		if ierr != nil {
			continue
		}
		if info.Type == ebpf.XDP {
			return uint32(id), nil
		}
	}
	return 0, fmt.Errorf("no XDP program found on %s", ifname)
}
