// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dkg2

import (
	"crypto/rand"
	"io"
	"testing"

	"github.com/luxfi/corona/sign"
)

// BenchmarkDKG2_Round1_Baseline captures the single-party Round 1 cost
// before GPU dispatch is wired in. The numbers feed the speedup
// comparison in BenchmarkDKG2_Round1_GPU (dkg2_gpu_test.go).
func BenchmarkDKG2_Round1_Baseline_5of7(b *testing.B)   { benchRound1Baseline(b, 7, 5) }
func BenchmarkDKG2_Round1_Baseline_7of11(b *testing.B)  { benchRound1Baseline(b, 11, 7) }
func BenchmarkDKG2_Round1_Baseline_14of21(b *testing.B) { benchRound1Baseline(b, 21, 14) }

func benchRound1Baseline(b *testing.B, n, t int) {
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
