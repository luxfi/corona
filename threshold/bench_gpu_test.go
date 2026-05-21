// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package threshold

import (
	"crypto/rand"
	"io"
	"testing"

	cgpu "github.com/luxfi/corona/gpu"
)

// BenchmarkPulsarSign measures the wall-clock cost of the 2-round
// Pulsar threshold protocol's *online* phase (Round1 + Round2 +
// Finalize, given a fresh GenerateKeys epoch). The IEEE S&P 2025
// Pulsar evaluation calls out a 0.6 s online phase across 5
// continents at the production shape; this bench gives the local
// upper bound (network RTT is excluded; the cost here is pure CPU /
// GPU compute).
//
// HONEST PERFORMANCE NOTE.
//
// At corona's production ring degree N=256 the single-poly Metal NTT
// is slower than the pure-Go ring.SubRing.NTT (lattice/gpu's own
// header documents this for every N up to 16384). The default
// corona/gpu threshold = 1024 keeps single-poly dispatch OFF at
// N=256, so BenchmarkPulsarSign_*_GPU here is effectively the same
// kernel as the CPU bench with a small dispatcher branch cost; bench
// noise dominates the comparison.
//
// The GPU win for Pulsar requires a BATCHED dispatch path that calls
// lattice/gpu.MontgomeryNTTContext.Forward(data, batch>=4) at the
// engine layer, bypassing the per-poly r.NTT() pinch point. That
// kernel slot exists (see lattice/gpu/gpu_cgo.go::BatchNTT) but is
// not yet plumbed through r.NTT — that's the v0.6+ NIST submission
// pipeline work referenced in corona/dkg2/dkg2_gpu_accel.go.
//
// CPU vs GPU pairs (one bench function each) let `go test -bench .`
// emit a side-by-side comparison without bench-fixture trickery; the
// GPU bench remains useful as a regression watchdog (any change that
// adds non-trivial dispatcher overhead will show up here).

func BenchmarkPulsarSign_2of3_CPU(b *testing.B)  { benchPulsarSign(b, 3, 2, false) }
func BenchmarkPulsarSign_2of3_GPU(b *testing.B)  { benchPulsarSign(b, 3, 2, true) }
func BenchmarkPulsarSign_5of7_CPU(b *testing.B)  { benchPulsarSign(b, 7, 5, false) }
func BenchmarkPulsarSign_5of7_GPU(b *testing.B)  { benchPulsarSign(b, 7, 5, true) }
func BenchmarkPulsarSign_7of11_CPU(b *testing.B) { benchPulsarSign(b, 11, 7, false) }
func BenchmarkPulsarSign_7of11_GPU(b *testing.B) { benchPulsarSign(b, 11, 7, true) }

// 14-of-21 — production Lux consensus shape.
func BenchmarkPulsarSign_14of21_CPU(b *testing.B) { benchPulsarSign(b, 21, 14, false) }
func BenchmarkPulsarSign_14of21_GPU(b *testing.B) { benchPulsarSign(b, 21, 14, true) }

func benchPulsarSign(b *testing.B, n, thr int, gpuOn bool) {
	if gpuOn {
		if err := cgpu.UseAccelerator(); err != nil {
			b.Fatalf("UseAccelerator: %v", err)
		}
	} else {
		cgpu.DisableAccelerator()
	}
	b.Cleanup(cgpu.DisableAccelerator)

	shares, _, err := GenerateKeys(thr, n, rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	signers := make([]*Signer, n)
	for i, sh := range shares {
		signers[i] = NewSigner(sh)
	}
	signerIDs := make([]int, n)
	for i := range signerIDs {
		signerIDs[i] = i
	}
	prfKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, prfKey); err != nil {
		b.Fatal(err)
	}
	msg := "bench-pulsar-sign-online"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sid := i + 1
		round1 := make(map[int]*Round1Data, n)
		for _, s := range signers {
			d := s.Round1(sid, prfKey, signerIDs)
			round1[d.PartyID] = d
		}
		round2 := make(map[int]*Round2Data, n)
		for _, s := range signers {
			d, err := s.Round2(sid, msg, prfKey, signerIDs, round1)
			if err != nil {
				b.Fatal(err)
			}
			round2[d.PartyID] = d
		}
		if _, err := signers[0].Finalize(round2); err != nil {
			b.Fatal(err)
		}
	}
}
