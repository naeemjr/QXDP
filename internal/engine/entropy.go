package engine

import (
	"fmt"
	"math"
)

type SketchHdrRow [128]uint32
type HKBucket struct {
	Fingerprint uint64
	Count       uint32
	SrcIPSample uint32
}
type SketchPLRow [256]HKBucket

type SketchState struct {
	ViewAHdr     [4]SketchHdrRow
	ViewBPayload [4]SketchPLRow
	PrngRing     [256]uint32
	PrngCursor   uint32
	Pad0         uint32
	PassPkts     uint64
	DropPkts     uint64
	PassBytes    uint64
	DropBytes    uint64
	Collisions   uint64
}

type SignatureResult struct {
	Centroid   uint64
	CareMask   uint64
	HammingMax uint32
	Divergence float64
	ViewAH     float64
	ViewBH     float64
	SrcH       float64
	Mode       string
}

func shannonEntropy(counts []uint64) float64 {
	var total uint64
	for _, c := range counts {
		total += c
	}
	if total == 0 {
		return 0
	}
	var h float64
	ft := float64(total)
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / ft
		h -= p * math.Log2(p)
	}
	return h
}

func AggregateSketchStates(perCPU []SketchState) SketchState {
	var agg SketchState
	for _, s := range perCPU {
		for r := 0; r < 4; r++ {
			for c := 0; c < 128; c++ {
				agg.ViewAHdr[r][c] += s.ViewAHdr[r][c]
			}
		}
		for r := 0; r < 4; r++ {
			for c := 0; c < 256; c++ {
				if s.ViewBPayload[r][c].Count > agg.ViewBPayload[r][c].Count {
					agg.ViewBPayload[r][c] = s.ViewBPayload[r][c]
				}
			}
		}
		agg.PassPkts += s.PassPkts
		agg.DropPkts += s.DropPkts
		agg.PassBytes += s.PassBytes
		agg.DropBytes += s.DropBytes
		agg.Collisions += s.Collisions
	}
	return agg
}

func AnalyzeAndExtractSignature(agg SketchState) SignatureResult {
	return AnalyzeAndExtractSignatureWithBaseline(agg, nil)
}

func AnalyzeAndExtractSignatureWithBaseline(agg SketchState, benignTokens []uint64) SignatureResult {
	viewACounts := make([]uint64, 128)
	for c := 0; c < 128; c++ {
		var sum uint64
		for r := 0; r < 4; r++ {
			sum += uint64(agg.ViewAHdr[r][c])
		}
		viewACounts[c] = sum
	}
	viewAH := shannonEntropy(viewACounts)

	viewBCounts := make([]uint64, 256)
	for c := 0; c < 256; c++ {
		var sum uint64
		for r := 0; r < 4; r++ {
			sum += uint64(agg.ViewBPayload[r][c].Count)
		}
		viewBCounts[c] = sum
	}
	viewBH := shannonEntropy(viewBCounts)

	srcMap := make(map[uint32]uint64)
	for r := 0; r < 4; r++ {
		for c := 0; c < 256; c++ {
			b := agg.ViewBPayload[r][c]
			if b.Count > 0 && b.SrcIPSample != 0 {
				srcMap[b.SrcIPSample] += uint64(b.Count)
			}
		}
	}
	srcCounts := make([]uint64, 0, len(srcMap))
	for _, v := range srcMap {
		srcCounts = append(srcCounts, v)
	}
	srcH := shannonEntropy(srcCounts)

	minViewH := math.Min(viewAH, viewBH)
	if minViewH < 0.001 {
		minViewH = 0.001
	}
	divergence := srcH / minViewH

	type heavyEntry struct {
		fp    uint64
		count uint32
	}
	var heavies []heavyEntry
	for r := 0; r < 4; r++ {
		for c := 0; c < 256; c++ {
			b := agg.ViewBPayload[r][c]
			if b.Count >= 2 {
				heavies = append(heavies, heavyEntry{b.Fingerprint, b.Count})
			}
		}
	}

	if len(heavies) == 0 {
		return SignatureResult{Divergence: divergence, ViewAH: viewAH, ViewBH: viewBH, SrcH: srcH, Mode: "C"}
	}

	var bestFP uint64
	var bestCount uint32
	for _, h := range heavies {
		if h.count > bestCount {
			bestCount = h.count
			bestFP = h.fp
		}
	}

	var bitOneCount [64]int
	var bitTotal int
	for _, h := range heavies {
		if h.count >= bestCount/4 {
			bitTotal++
			for b := 0; b < 64; b++ {
				if (h.fp>>uint(b))&1 == (bestFP>>uint(b))&1 {
					bitOneCount[b]++
				}
			}
		}
	}

	var careMask uint64
	if bitTotal > 0 {
		threshold := float64(bitTotal) * 0.95
		for b := 0; b < 64; b++ {
			if float64(bitOneCount[b]) >= threshold {
				careMask |= 1 << uint(b)
			}
		}
	}

	// Exclude bits also invariant in benign traffic
	if len(benignTokens) > 0 && careMask != 0 {
		centroidBit := func(b int) uint64 { return (bestFP >> uint(b)) & 1 }
		for b := 0; b < 64; b++ {
			if careMask&(1<<uint(b)) == 0 {
				continue
			}
			var benignAgree int
			for _, bt := range benignTokens {
				if (bt>>uint(b))&1 == centroidBit(b) {
					benignAgree++
				}
			}
			if float64(benignAgree)/float64(len(benignTokens)) > 0.5 {
				careMask &^= 1 << uint(b)
			}
		}
	}

	// --- Context-Aware Mode Detection ---
	// Count invariant care bits per token zone
	anchorBits := swarPopcount64(careMask & 0x0000FFFF00000000)  // bits 32..47
	shingleBits := swarPopcount64(careMask & 0x00000000FFFFFFFF) // bits 0..31
	payloadBits := anchorBits + shingleBits

	mode := "A"

	if payloadBits < 4 {
		// Mode C: Encrypted / high-entropy / no-payload fallback
		mode = "C"
		careMask &= 0xFFFF000000000000
	} else if anchorBits < 4 && shingleBits >= 4 {
		// Mode B: Shift-invariant shingle lock (anchor noisy from prepend)
		mode = "B"
		careMask &= 0xFFFF0000FFFFFFFF
	}

	if careMask == 0 {
		careMask = 0xFFFF000000000000
		mode = "C"
	}

	// Conservative theta: max Hamming distance among attack heavies
	var maxDist uint32
	for _, h := range heavies {
		if h.count >= bestCount/4 {
			diff := (bestFP ^ h.fp) & careMask
			d := swarPopcount64(diff)
			if d > maxDist {
				maxDist = d
			}
		}
	}

	// Calibrate against benign
	if len(benignTokens) > 0 && careMask != 0 {
		var minBenignDist uint32 = 64
		for _, bt := range benignTokens {
			d := swarPopcount64((bestFP ^ bt) & careMask)
			if d < minBenignDist {
				minBenignDist = d
			}
		}
		if maxDist+1 >= minBenignDist && minBenignDist > 1 {
			maxDist = minBenignDist - 2
		}
	} else {
		maxDist += 1
	}

	// Mode C cap: header-only needs tight theta
	if mode == "C" && maxDist > 1 {
		maxDist = 1
	}

	return SignatureResult{
		Centroid:   bestFP,
		CareMask:   careMask,
		HammingMax: maxDist,
		Divergence: divergence,
		ViewAH:     viewAH,
		ViewBH:     viewBH,
		SrcH:       srcH,
		Mode:       mode,
	}
}

func swarPopcount64(x uint64) uint32 {
	x -= (x >> 1) & 0x5555555555555555
	x = (x & 0x3333333333333333) + ((x >> 2) & 0x3333333333333333)
	x = (x + (x >> 4)) & 0x0F0F0F0F0F0F0F0F
	return uint32((x * 0x0101010101010101) >> 56)
}

func (r SignatureResult) String() string {
	return fmt.Sprintf("Centroid=0x%016X CareMask=0x%016X Theta=%d Γ=%.3f H(src)=%.3f H(A)=%.3f H(B)=%.3f Mode=%s",
		r.Centroid, r.CareMask, r.HammingMax, r.Divergence, r.SrcH, r.ViewAH, r.ViewBH, r.Mode)
}
