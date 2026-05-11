// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package sign

import (
	"math/big"
	"testing"

	"github.com/luxfi/corona/hash"
	"github.com/luxfi/corona/primitives"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/sampling"
	"github.com/luxfi/lattice/v7/utils/structs"
)

// TestSignProtocolRoundTripUnderBothSuites runs Gen → SignRound1 →
// SignRound2Preprocess → SignRound2 → SignFinalize → Verify under each
// available HashSuite (Pulsar-SHA3 and Pulsar-BLAKE3) and asserts the
// resulting signature verifies. The Sign and Verify paths must thread the
// same suite end-to-end; mixing suites must fail verification.
func TestSignProtocolRoundTripUnderBothSuites(t *testing.T) {
	// Package-level K and Threshold are set by local.go callers. Pin
	// them for this test to keep it self-contained and fast.
	K = 3
	Threshold = K
	defer func() { K = 0; Threshold = 0 }()

	suites := []struct {
		name  string
		suite hash.HashSuite
	}{
		{"Pulsar-SHA3", hash.NewPulsarSHA3()},
		{"Pulsar-BLAKE3", hash.NewPulsarBLAKE3()},
	}

	for _, sc := range suites {
		sc := sc
		t.Run(sc.name, func(t *testing.T) {
			runSignVerify(t, sc.suite, true)
		})
	}

	// Cross-suite mixing: Sign under SHA3, Verify under BLAKE3 → must fail.
	t.Run("CrossSuiteMixingRejected", func(t *testing.T) {
		sig, A, mu, b, c, delta, r, rXi, rNu := signOnly(t, hash.NewPulsarSHA3())
		// Same suite → ok.
		if !VerifyWithSuite(hash.NewPulsarSHA3(), r, rXi, rNu, sig, A, mu, b, c, delta) {
			t.Fatal("SHA3 self-verify must succeed")
		}
		// Different suite → must reject.
		if VerifyWithSuite(hash.NewPulsarBLAKE3(), r, rXi, rNu, sig, A, mu, b, c, delta) {
			t.Fatal("cross-suite verify (SHA3 sign / BLAKE3 verify) must reject — F22 separation violated")
		}
	})
}

// signOnly drives the Sign protocol to completion under `suite` and returns
// the artifacts a Verify call needs.
func signOnly(t *testing.T, suite hash.HashSuite) (
	structs.Vector[ring.Poly],
	structs.Matrix[ring.Poly],
	string,
	structs.Vector[ring.Poly],
	ring.Poly,
	structs.Vector[ring.Poly],
	*ring.Ring,
	*ring.Ring,
	*ring.Ring,
) {
	t.Helper()
	r, err := ring.NewRing(1<<LogN, []uint64{Q})
	if err != nil {
		t.Fatal(err)
	}
	// QXi and QNu are not NTT-prime; lattice/ring returns a partially
	// constructed ring with a non-nil error. Sign/RestoreVector + RoundVector
	// only need the modulus + storage, which the partial ring provides.
	// This matches how cmd/sign_oracle and sign/local.go construct these.
	rXi, _ := ring.NewRing(1<<LogN, []uint64{QXi})
	rNu, _ := ring.NewRing(1<<LogN, []uint64{QNu})

	randomKey := make([]byte, KeySize)
	prng, _ := sampling.NewKeyedPRNG(randomKey)
	uniformSampler := ring.NewUniformSampler(prng, r)

	parties := make([]*Party, K)
	for i := range parties {
		p, _ := sampling.NewKeyedPRNG(randomKey)
		us := ring.NewUniformSampler(p, r)
		parties[i] = NewPartyWithSuite(i, r, rXi, rNu, us, suite)
	}

	T := make([]int, K)
	for i := 0; i < K; i++ {
		T[i] = i
	}
	lagrangeCoeffs := primitives.ComputeLagrangeCoefficients(r, T, big.NewInt(int64(Q)))

	A, skShares, seeds, MACKeys, b := Gen(r, rXi, uniformSampler, randomKey, lagrangeCoeffs)
	for id := 0; id < K; id++ {
		parties[id].SkShare = skShares[id]
		parties[id].Seed = seeds
		parties[id].MACKeys = MACKeys[id]
	}

	mu := "round-trip-test-message"
	sid := 1
	PRFKey := primitives.GenerateRandomSeed()
	D := make(map[int]structs.Matrix[ring.Poly])
	MACs := make(map[int]map[int][]byte)
	for _, id := range T {
		r.NTT(lagrangeCoeffs[id], lagrangeCoeffs[id])
		r.MForm(lagrangeCoeffs[id], lagrangeCoeffs[id])
		parties[id].Lambda = lagrangeCoeffs[id]
		parties[id].Seed = seeds
		D[id], MACs[id] = parties[id].SignRound1(A, sid, []byte(PRFKey), T)
	}

	z := make(map[int]structs.Vector[ring.Poly])
	for _, id := range T {
		valid, DSum, transcriptHash := parties[id].SignRound2Preprocess(A, b, D, MACs, sid, T)
		if !valid {
			t.Fatalf("MAC verification failed for party %d under suite %s", id, suite.ID())
		}
		z[id] = parties[id].SignRound2(A, b, DSum, sid, mu, T, []byte(PRFKey), transcriptHash)
	}

	final := parties[0]
	c, sig, delta := final.SignFinalize(z, A, b)
	return sig, A, mu, b, c, delta, r, rXi, rNu
}

// runSignVerify drives Sign + Verify under `suite` and asserts the signature
// verifies. `expectValid` toggles the pass/fail expectation.
func runSignVerify(t *testing.T, suite hash.HashSuite, expectValid bool) {
	t.Helper()
	sig, A, mu, b, c, delta, r, rXi, rNu := signOnly(t, suite)
	got := VerifyWithSuite(suite, r, rXi, rNu, sig, A, mu, b, c, delta)
	if got != expectValid {
		t.Fatalf("Verify under %s: got %v want %v", suite.ID(), got, expectValid)
	}
}
