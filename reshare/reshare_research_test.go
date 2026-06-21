// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build corona_research

// reshare_research_test.go holds the Reshare/Refresh tests that reconstruct the
// master secret (via the research-only reshare.Verify) to assert secret
// preservation. They are gated behind `corona_research` because the
// reconstruction helper is gated there too; run with -tags corona_research.
// The shared test helpers (canonicalRing, makeStandardShamirShares, pickSecret,
// equalSecrets, fakeRand, …) live in reshare_test.go, which is untagged and so
// compiles in both the default and the research build.
package reshare

import (
	"bytes"
	"testing"

	"github.com/luxfi/corona/primitives"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/structs"
)

// TestReshareSecretInvariant — the master secret is preserved across an
// arbitrary reshare. Builds shares of a known secret, runs Reshare, and
// reconstructs the secret from the new shares to verify equality.
func TestReshareSecretInvariant(t *testing.T) {
	r := canonicalRing(t)

	// Old committee: 5 parties with threshold 3.
	tOld, nOld := 3, 5
	secret := pickSecret(r, "secret-invariant", testNVec)
	rs := newFakeRand([]byte("old-shamir-rng-seed"))
	oldShares, err := makeStandardShamirShares(r, secret, tOld, nOld, rs)
	if err != nil {
		t.Fatal(err)
	}

	// Sanity: old shares interpolate to secret.
	rec, err := Verify(r, oldShares, tOld)
	if err != nil {
		t.Fatal(err)
	}
	if !equalSecrets(rec, secret) {
		t.Fatal("old shares do not reconstruct the planted secret")
	}

	// New committee: 7 parties with threshold 5.
	tNew := 5
	newSet := []int{10, 11, 12, 13, 14, 15, 16}

	rsReshare := newFakeRand([]byte("reshare-rng-seed"))
	newShares, err := Reshare(r, oldShares, tOld, newSet, tNew, rsReshare)
	if err != nil {
		t.Fatalf("Reshare: %v", err)
	}
	if len(newShares) != len(newSet) {
		t.Fatalf("expected %d new shares, got %d", len(newSet), len(newShares))
	}

	// New shares interpolate to the same secret.
	rec2, err := Verify(r, newShares, tNew)
	if err != nil {
		t.Fatal(err)
	}
	if !equalSecrets(rec2, secret) {
		t.Fatal("RESHARE BROKE THE SECRET — new shares interpolate to a different value")
	}
}

// TestReshareThresholdShortfall — fewer than t_new new shares cannot
// reconstruct the secret. We Lagrange-interpolate (t_new - 1) of them
// and check the result differs from the secret with overwhelming
// probability (one big.Int comparison suffices given Z_q's size).
func TestReshareThresholdShortfall(t *testing.T) {
	r := canonicalRing(t)

	tOld, nOld := 2, 3
	secret := pickSecret(r, "shortfall", testNVec)
	rs := newFakeRand([]byte("old-shortfall-rng"))
	oldShares, err := makeStandardShamirShares(r, secret, tOld, nOld, rs)
	if err != nil {
		t.Fatal(err)
	}

	tNew := 4
	newSet := []int{20, 21, 22, 23, 24, 25}
	rsReshare := newFakeRand([]byte("shortfall-reshare"))
	newShares, err := Reshare(r, oldShares, tOld, newSet, tNew, rsReshare)
	if err != nil {
		t.Fatal(err)
	}

	// Take only (tNew - 1) shares.
	short := make(map[int]Share, tNew-1)
	for i, j := range newSet {
		if i >= tNew-1 {
			break
		}
		short[j] = newShares[j]
	}

	// Lagrange-interpolate at X=0 with too-few shares: the result must
	// differ from secret. Given Z_q has 2^48 elements per coordinate,
	// false positives (collision) happen with prob 2^-48 per coordinate.
	// So even one of the testNVec * 256 coordinates differing is enough.
	rec, err := Verify(r, short, tNew-1)
	if err != nil {
		t.Fatal(err)
	}
	if equalSecrets(rec, secret) {
		t.Fatal("(t_new - 1)-of-n interpolation should not recover the secret")
	}
}

// TestRereshareIdempotent — resharing twice in a row (with different
// fresh RNG each time) still preserves the master secret.
func TestRereshareIdempotent(t *testing.T) {
	r := canonicalRing(t)

	tOld, nOld := 2, 3
	secret := pickSecret(r, "idempotent", testNVec)
	rs := newFakeRand([]byte("idem-old"))
	oldShares, err := makeStandardShamirShares(r, secret, tOld, nOld, rs)
	if err != nil {
		t.Fatal(err)
	}

	// First reshare: 2-of-3 → 3-of-5 (committee {40..44}).
	tMid := 3
	midSet := []int{40, 41, 42, 43, 44}
	mid, err := Reshare(r, oldShares, tOld, midSet, tMid, newFakeRand([]byte("idem-r1")))
	if err != nil {
		t.Fatal(err)
	}

	// Verify mid interpolates to secret.
	recMid, err := Verify(r, mid, tMid)
	if err != nil {
		t.Fatal(err)
	}
	if !equalSecrets(recMid, secret) {
		t.Fatal("first reshare lost the secret")
	}

	// Second reshare: 3-of-5 → 5-of-7 (committee {50..56}).
	tFinal := 5
	finalSet := []int{50, 51, 52, 53, 54, 55, 56}
	final, err := Reshare(r, mid, tMid, finalSet, tFinal, newFakeRand([]byte("idem-r2")))
	if err != nil {
		t.Fatal(err)
	}

	recFinal, err := Verify(r, final, tFinal)
	if err != nil {
		t.Fatal(err)
	}
	if !equalSecrets(recFinal, secret) {
		t.Fatal("second reshare lost the secret")
	}
}

// TestRefreshSecretInvariant — the same-committee Refresh kernel
// preserves the master secret while changing every share. Proves the
// HJKY97 zero-polynomial primitive correct.
func TestRefreshSecretInvariant(t *testing.T) {
	r := canonicalRing(t)

	tThreshold, n := 3, 5
	secret := pickSecret(r, "refresh-invariant", testNVec)
	rs := newFakeRand([]byte("refresh-old-rng"))
	shares, err := makeStandardShamirShares(r, secret, tThreshold, n, rs)
	if err != nil {
		t.Fatal(err)
	}

	rec, err := Verify(r, shares, tThreshold)
	if err != nil {
		t.Fatal(err)
	}
	if !equalSecrets(rec, secret) {
		t.Fatal("baseline shares do not interpolate to secret")
	}

	refreshed, err := Refresh(r, shares, tThreshold,
		newFakeRand([]byte("refresh-rng-seed")))
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if len(refreshed) != n {
		t.Fatalf("expected %d refreshed shares, got %d", n, len(refreshed))
	}

	// 1. Refreshed shares interpolate to the SAME secret.
	rec2, err := Verify(r, refreshed, tThreshold)
	if err != nil {
		t.Fatal(err)
	}
	if !equalSecrets(rec2, secret) {
		t.Fatal("Refresh changed the master secret")
	}

	// 2. Every party's share value actually changed (probability of
	// collision per coordinate is 2^-48, so a single match across the
	// nVec * 256 coordinates is overwhelmingly unlikely).
	for j := range shares {
		oldFlat := uint64sToBytes(flattenShare(shares[j]))
		newFlat := uint64sToBytes(flattenShare(refreshed[j]))
		if bytes.Equal(oldFlat, newFlat) {
			t.Fatalf("party %d: Refresh did not change the share value", j)
		}
	}
}

// TestReshareWithSignGenShares — bridges from the production
// sign.Gen-style "optimized" share representation (t = K, special
// Lagrange basis) into the standard-Shamir representation we operate
// on. We use the existing primitives.ShamirSecretSharingGeneral as a
// proxy: it produces standard-Shamir shares directly. This proves the
// reshare API works against the same primitives used elsewhere in the
// codebase, not just the hand-rolled makeStandardShamirShares helper
// above.
func TestReshareWithSignGenShares(t *testing.T) {
	r := canonicalRing(t)
	q := r.Modulus()
	_ = q

	secret := pickSecret(r, "primitives-bridge", testNVec)

	// Use the corona primitives' standard Shamir variant.
	tOld, nOld := 3, 5
	primSharesMap := primitives.ShamirSecretSharingGeneral(
		r, secret, tOld, nOld,
	)
	// Convert from 0-indexed map (primitives convention) to 1-indexed
	// map (reshare convention).
	oldShares := make(map[int]Share, nOld)
	for partyIdx, vec := range primSharesMap {
		oldShares[partyIdx+1] = structs.Vector[ring.Poly](vec)
	}

	// Sanity: reconstruct via reshare.Verify.
	rec, err := Verify(r, oldShares, tOld)
	if err != nil {
		t.Fatal(err)
	}
	if !equalSecrets(rec, secret) {
		t.Fatal("primitives-produced shares failed reshare.Verify reconstruction")
	}

	// Reshare 3-of-5 → 5-of-9.
	tNew := 5
	newSet := []int{1, 2, 3, 4, 5, 6, 7, 8, 9}
	newShares, err := Reshare(r, oldShares, tOld, newSet, tNew,
		newFakeRand([]byte("primitives-bridge-reshare")))
	if err != nil {
		t.Fatal(err)
	}

	rec2, err := Verify(r, newShares, tNew)
	if err != nil {
		t.Fatal(err)
	}
	if !equalSecrets(rec2, secret) {
		t.Fatal("reshare with primitives-style input lost the secret")
	}
}
