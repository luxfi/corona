// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dkg2

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/luxfi/corona/sign"
	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/structs"
)

// TestDKG2_GPU_ByteEqual is the core correctness theorem: the CPU and
// GPU dispatch legs of Round 1 MUST produce byte-identical output for
// the same RNG seed. A divergence here would be a cross-validator KAT
// failure during a live Pedersen DKG and would halt the consensus path
// the ceremony bootstraps.
//
// We exercise the same (n, t) shapes the canonical KATs cover (2-of-3,
// 3-of-5, 5-of-7, 7-of-11) plus the production target n=21, t=14.
func TestDKG2_GPU_ByteEqual(t *testing.T) {
	for _, tc := range []struct {
		name string
		n, t int
	}{
		{"n3_t2", 3, 2},
		{"n5_t3", 5, 3},
		{"n7_t5", 7, 5},
		{"n11_t7", 11, 7},
		{"n21_t14", 21, 14},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			params, err := NewParams()
			if err != nil {
				t.Fatal(err)
			}

			// Same seed for both legs — byte-equality requires the
			// same input.
			seed := make([]byte, sign.KeySize)
			for i := range seed {
				seed[i] = byte(0x5A ^ (i * 31) ^ tc.n ^ (tc.t << 1))
			}

			runLeg := func(gpuOn bool) *Round1Output {
				prev := SetDKG2GPUForTest(gpuOn)
				defer SetDKG2GPUForTest(prev)
				sess, err := NewDKGSession(params, 0, tc.n, tc.t, nil)
				if err != nil {
					t.Fatalf("NewDKGSession: %v", err)
				}
				out, err := sess.Round1WithSeed(seed)
				if err != nil {
					t.Fatalf("Round1WithSeed gpu=%v: %v", gpuOn, err)
				}
				return out
			}

			cpu := runLeg(false)
			gpu := runLeg(true)

			// Commits: byte-equal across both legs.
			if len(cpu.Commits) != len(gpu.Commits) {
				t.Fatalf("commit count: cpu=%d gpu=%d", len(cpu.Commits), len(gpu.Commits))
			}
			cpuBytes, err := cpu.SerializeCommits()
			if err != nil {
				t.Fatal(err)
			}
			gpuBytes, err := gpu.SerializeCommits()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(cpuBytes, gpuBytes) {
				t.Fatalf("commit bytes mismatch: cpu_len=%d gpu_len=%d head_cpu=%x head_gpu=%x",
					len(cpuBytes), len(gpuBytes), cpuBytes[:32], gpuBytes[:32])
			}

			// Shares and blinds: byte-equal per recipient.
			if len(cpu.Shares) != len(gpu.Shares) || len(cpu.Blinds) != len(gpu.Blinds) {
				t.Fatalf("share/blind map size mismatch")
			}
			for j := 0; j < tc.n; j++ {
				if !vectorBytesEqual(cpu.Shares[j], gpu.Shares[j]) {
					t.Fatalf("share[%d] bytes mismatch", j)
				}
				if !vectorBytesEqual(cpu.Blinds[j], gpu.Blinds[j]) {
					t.Fatalf("blind[%d] bytes mismatch", j)
				}
			}
		})
	}
}

// vectorBytesEqual returns true if two Vector[Poly] serialise byte-equal.
func vectorBytesEqual(a, b structs.Vector[ring.Poly]) bool {
	if len(a) != len(b) {
		return false
	}
	var bufA, bufB bytes.Buffer
	if _, err := a.WriteTo(&bufA); err != nil {
		return false
	}
	if _, err := b.WriteTo(&bufB); err != nil {
		return false
	}
	return bytes.Equal(bufA.Bytes(), bufB.Bytes())
}

// TestDKG2_GPU_RoundTripVerify confirms the GPU-produced shares verify
// against the GPU-produced commits via the existing Pedersen identity
// check. This is the cryptographic correctness gate (independent of the
// byte-equal test): even if the CPU and GPU legs produced different
// outputs, both would have to verify under their own commits — and a
// share that satisfies the Pedersen identity is a valid Pedersen-DKG
// contribution by construction.
func TestDKG2_GPU_RoundTripVerify(t *testing.T) {
	prev := SetDKG2GPUForTest(true)
	defer SetDKG2GPUForTest(prev)

	params, err := NewParams()
	if err != nil {
		t.Fatal(err)
	}
	const n, threshold = 7, 5
	sess, err := NewDKGSession(params, 0, n, threshold, nil)
	if err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, sign.KeySize)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		t.Fatal(err)
	}
	out, err := sess.Round1WithSeed(seed)
	if err != nil {
		t.Fatal(err)
	}

	// Every (share[j], blind[j]) MUST verify against the commit vector.
	A := sess.APublic()
	B := sess.BPublic()
	for j := 0; j < n; j++ {
		ok, err := VerifyShareAgainstCommits(params, A, B,
			out.Shares[j], out.Blinds[j], out.Commits, j, threshold)
		if err != nil {
			t.Fatalf("VerifyShareAgainstCommits j=%d: %v", j, err)
		}
		if !ok {
			t.Fatalf("GPU-produced share[%d] FAILED Pedersen verify under GPU-produced commits", j)
		}
	}
}

// TestDKG2_GPU_FullCeremony runs the canonical multi-party Round 1 →
// Round 2 ceremony with GPU dispatch on. Hooks into the same harness
// used by TestDKG2_2of3 etc; only difference is the dispatch toggle.
func TestDKG2_GPU_FullCeremony(t *testing.T) {
	prev := SetDKG2GPUForTest(true)
	defer SetDKG2GPUForTest(prev)
	runPedersenDKG(t, 7, 5)
}

// BenchmarkDKG2_GPU_Round1_*_CPU and _GPU measure the speedup of the
// parallel byte-slot fan-out at production sizes.
//
// On Apple M1 Max with 10 GOMAXPROCS the expected speedup is roughly
// linear in the t·N axis (NTT calls are the dominant cost); the n axis
// also benefits but Horner is cheaper per step than the NTT path.
func BenchmarkDKG2_GPU_Round1_5of7_CPU(b *testing.B) {
	prev := SetDKG2GPUForTest(false)
	defer SetDKG2GPUForTest(prev)
	benchRound1(b, 7, 5)
}

func BenchmarkDKG2_GPU_Round1_5of7_GPU(b *testing.B) {
	prev := SetDKG2GPUForTest(true)
	defer SetDKG2GPUForTest(prev)
	benchRound1(b, 7, 5)
}

func BenchmarkDKG2_GPU_Round1_7of11_CPU(b *testing.B) {
	prev := SetDKG2GPUForTest(false)
	defer SetDKG2GPUForTest(prev)
	benchRound1(b, 11, 7)
}

func BenchmarkDKG2_GPU_Round1_7of11_GPU(b *testing.B) {
	prev := SetDKG2GPUForTest(true)
	defer SetDKG2GPUForTest(prev)
	benchRound1(b, 11, 7)
}

// 14-of-21: the production Lux consensus committee shape (n=21, t=14)
// is the headline benchmark the task asks for.
func BenchmarkDKG2_GPU_Round1_14of21_CPU(b *testing.B) {
	prev := SetDKG2GPUForTest(false)
	defer SetDKG2GPUForTest(prev)
	benchRound1(b, 21, 14)
}

func BenchmarkDKG2_GPU_Round1_14of21_GPU(b *testing.B) {
	prev := SetDKG2GPUForTest(true)
	defer SetDKG2GPUForTest(prev)
	benchRound1(b, 21, 14)
}

func benchRound1(b *testing.B, n, t int) {
	params, err := NewParams()
	if err != nil {
		b.Fatal(err)
	}
	sess, err := NewDKGSession(params, 0, n, t, nil)
	if err != nil {
		b.Fatal(err)
	}
	seed := make([]byte, sign.KeySize)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := sess.Round1WithSeed(seed); err != nil {
			b.Fatal(err)
		}
	}
}
