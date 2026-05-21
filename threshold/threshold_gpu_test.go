// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package threshold

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	cgpu "github.com/luxfi/corona/gpu"
)

// deterministicReader is a SHA-256 keystream over a 32-byte seed,
// suitable as an io.Reader for GenerateKeys. Two calls with the same
// seed produce the same bytes, which fixes the trustedDealerKey across
// the CPU and GPU legs of this test.
type deterministicReader struct {
	seed   [32]byte
	block  [32]byte
	offset int
	ctr    uint64
}

func newDeterministicReader(seed [32]byte) *deterministicReader {
	r := &deterministicReader{seed: seed}
	r.refill()
	return r
}

func (r *deterministicReader) refill() {
	var ctrBuf [8]byte
	binary.BigEndian.PutUint64(ctrBuf[:], r.ctr)
	h := sha256.New()
	h.Write(r.seed[:])
	h.Write(ctrBuf[:])
	sum := h.Sum(nil)
	copy(r.block[:], sum)
	r.offset = 0
	r.ctr++
}

func (r *deterministicReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if r.offset >= len(r.block) {
			r.refill()
		}
		m := copy(p[n:], r.block[r.offset:])
		r.offset += m
		n += m
	}
	return n, nil
}

// TestThresholdSign_CPU_vs_GPU_ByteIdentical — running the full
// 2-round Pulsar signing protocol with GPU NTT dispatch off and then
// on (same deterministic dealer randomness, same message) MUST yield
// byte-identical signature components. This is the core correctness
// gate: a single off-by-one in the GPU NTT and the aggregator rejects
// the share. The contract is defended by lattice/gpu (Montgomery
// context byte-equal to ring.SubRing.NTT) and here we enforce it
// end-to-end through corona's signing flow.
func TestThresholdSign_CPU_vs_GPU_ByteIdentical(t *testing.T) {
	// Same dealer randomness on both legs.
	var seed [32]byte
	copy(seed[:], "byte-equal-gpu-vs-cpu-pulsar-rt!")

	const k = 3
	const thr = 2
	sessionID := 7
	prfKey := []byte("byte-equal-prf-32-bytes-long-aaaa")
	message := "byte-equal-message-cpu-vs-gpu"
	signerIDs := []int{0, 1, 2}

	runLeg := func(gpuOn bool) ([]byte, []byte, []byte) {
		t.Helper()
		if gpuOn {
			// Force-engage the GPU path even at N=256, where the
			// production threshold would leave dispatch off. The
			// goal here is correctness (byte-equal across paths),
			// not throughput.
			if err := cgpu.UseAcceleratorForce(); err != nil {
				t.Fatalf("UseAcceleratorForce: %v", err)
			}
		} else {
			cgpu.DisableAccelerator()
		}
		shares, groupKey, err := GenerateKeys(thr, k, newDeterministicReader(seed))
		if err != nil {
			t.Fatalf("GenerateKeys (gpu=%v): %v", gpuOn, err)
		}

		signers := make([]*Signer, k)
		for i, sh := range shares {
			signers[i] = NewSigner(sh)
		}

		round1 := make(map[int]*Round1Data)
		for _, s := range signers {
			d := s.Round1(sessionID, prfKey, signerIDs)
			round1[d.PartyID] = d
		}

		round2 := make(map[int]*Round2Data)
		for _, s := range signers {
			d, err := s.Round2(sessionID, message, prfKey, signerIDs, round1)
			if err != nil {
				t.Fatalf("Round2 (gpu=%v): %v", gpuOn, err)
			}
			round2[d.PartyID] = d
		}

		sig, err := signers[0].Finalize(round2)
		if err != nil {
			t.Fatalf("Finalize (gpu=%v): %v", gpuOn, err)
		}
		if !Verify(groupKey, message, sig) {
			t.Fatalf("self-verify failed (gpu=%v)", gpuOn)
		}

		var cBuf, zBuf, dBuf bytes.Buffer
		if _, err := sig.C.WriteTo(&cBuf); err != nil {
			t.Fatal(err)
		}
		if _, err := sig.Z.WriteTo(&zBuf); err != nil {
			t.Fatal(err)
		}
		if _, err := sig.Delta.WriteTo(&dBuf); err != nil {
			t.Fatal(err)
		}
		return cBuf.Bytes(), zBuf.Bytes(), dBuf.Bytes()
	}

	t.Cleanup(cgpu.DisableAccelerator)

	cpuC, cpuZ, cpuD := runLeg(false)
	gpuC, gpuZ, gpuD := runLeg(true)

	if !bytes.Equal(cpuC, gpuC) {
		t.Fatalf("sig.C differs: cpu=%x gpu=%x", head(cpuC), head(gpuC))
	}
	if !bytes.Equal(cpuZ, gpuZ) {
		t.Fatalf("sig.Z differs: cpu=%x gpu=%x", head(cpuZ), head(gpuZ))
	}
	if !bytes.Equal(cpuD, gpuD) {
		t.Fatalf("sig.Delta differs: cpu=%x gpu=%x", head(cpuD), head(gpuD))
	}
}

func head(b []byte) []byte {
	if len(b) > 32 {
		return b[:32]
	}
	return b
}

