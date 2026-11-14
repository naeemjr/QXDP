package engine

import (
	"fmt"

	"github.com/cilium/ebpf"
)

type SpecializedProgram struct {
	Spec    *ebpf.CollectionSpec
	Coll    *ebpf.Collection
	Program *ebpf.Program
}

func CompileSpecializedProgram(spec *ebpf.CollectionSpec, sig SignatureResult) (*SpecializedProgram, error) {
	return CompileSpecializedProgramWithTap(spec, sig, false)
}

func CompileSpecializedProgramWithTap(spec *ebpf.CollectionSpec, sig SignatureResult, tapEnabled bool) (*SpecializedProgram, error) {
	return CompileMultiSigProgram(spec, []SignatureResult{sig}, tapEnabled)
}

func CompileMultiSigProgram(spec *ebpf.CollectionSpec, sigs []SignatureResult, tapEnabled bool) (*SpecializedProgram, error) {
	specCopy := spec.Copy()

	var tapVal uint32
	if tapEnabled {
		tapVal = 1
	}
	if err := setVar(specCopy, "CFG_ENABLE_TAP", tapVal); err != nil {
		return nil, err
	}

	for i, sig := range sigs {
		if i >= 8 {
			break
		}
		slot := i + 1
		if err := setVar(specCopy, fmt.Sprintf("CFG_SIG_CENTROID_%d", slot), sig.Centroid); err != nil {
			return nil, err
		}
		if err := setVar(specCopy, fmt.Sprintf("CFG_CARE_MASK_%d", slot), sig.CareMask); err != nil {
			return nil, err
		}
		if err := setVar(specCopy, fmt.Sprintf("CFG_HAMMING_MAX_%d", slot), sig.HammingMax); err != nil {
			return nil, err
		}
	}

	coll, err := ebpf.NewCollectionWithOptions(specCopy, ebpf.CollectionOptions{})
	if err != nil {
		return nil, fmt.Errorf("load specialized collection: %w", err)
	}

	prog, ok := coll.Programs["qxdp_aegis"]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("program qxdp_aegis not found in specialized collection")
	}

	return &SpecializedProgram{
		Spec:    specCopy,
		Coll:    coll,
		Program: prog,
	}, nil
}

func setVar(spec *ebpf.CollectionSpec, name string, val interface{}) error {
	v, ok := spec.Variables[name]
	if !ok {
		return fmt.Errorf("variable %s not found in spec", name)
	}
	switch tv := val.(type) {
	case uint64:
		return v.Set(tv)
	case uint32:
		return v.Set(tv)
	default:
		return fmt.Errorf("unsupported type for %s", name)
	}
}

func (sp *SpecializedProgram) Close() {
	if sp.Coll != nil {
		sp.Coll.Close()
	}
}
