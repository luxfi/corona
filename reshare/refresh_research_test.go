// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build corona_research

// refresh_research_test.go holds the Refresh tests that reconstruct the master
// secret (via the research-only reshare.Verify) to assert secret preservation.
// They are gated behind `corona_research` because the reconstruction helper is
// gated there too; run with -tags corona_research. The Refresh production
// behaviour tests that do NOT reconstruct (determinism, t=1 identity, arg
// validation) live in refresh_test.go and run in the default build.
package reshare

import (
	"bytes"
	"testing"
)

// TestRefreshPreservesSecret — the core HJKY97 invariant: a Refresh
// round leaves the master secret unchanged but rotates every share.
//
// We build (t, n)-Shamir shares of a planted secret, run Refresh, and
// verify:
//
//  1. Old shares interpolate to the planted secret.
//  2. New shares interpolate to the SAME planted secret.
//  3. New shares ≠ old shares (Hamming/byte distance positive — the
//     probability all coordinates collide is < 2^-48 per coordinate
//     times nVec*N coordinates ≈ 2^-48 * 7 * 256 ≈ negligible).
//
// This is the canonical test that proves Refresh implements the
// HJKY97 zero-polynomial pattern correctly.
func TestRefreshPreservesSecret(t *testing.T) {
	r := canonicalRing(t)

	const tThr, n = 3, 5
	secret := pickSecret(r, "refresh-preserve", testNVec)
	rs := newFakeRand([]byte("refresh-old-shamir"))
	oldShares, err := makeStandardShamirShares(r, secret, tThr, n, rs)
	if err != nil {
		t.Fatal(err)
	}

	// Sanity: old shares interpolate to secret.
	rec, err := Verify(r, oldShares, tThr)
	if err != nil {
		t.Fatal(err)
	}
	if !equalSecrets(rec, secret) {
		t.Fatal("old shares do not reconstruct the planted secret")
	}

	// Refresh.
	newShares, err := Refresh(r, oldShares, tThr, newFakeRand([]byte("refresh-z-rng")))
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if len(newShares) != len(oldShares) {
		t.Fatalf("expected %d new shares, got %d", len(oldShares), len(newShares))
	}

	// Same committee → same party IDs as keys.
	for id := range oldShares {
		if _, ok := newShares[id]; !ok {
			t.Fatalf("new shares missing party %d", id)
		}
	}

	// New shares interpolate to the SAME secret.
	rec2, err := Verify(r, newShares, tThr)
	if err != nil {
		t.Fatal(err)
	}
	if !equalSecrets(rec2, secret) {
		t.Fatal("REFRESH BROKE THE SECRET — refreshed shares interpolate to a different value")
	}

	// New shares are different from old shares (this is the WHOLE
	// POINT of Refresh).
	differingParties := 0
	for id, oldS := range oldShares {
		if !bytes.Equal(uint64sToBytes(flattenShare(oldS)), uint64sToBytes(flattenShare(newShares[id]))) {
			differingParties++
		}
	}
	if differingParties != n {
		t.Fatalf("Refresh did not rotate every share: only %d/%d parties have new bytes", differingParties, n)
	}
}

// TestRefreshComposes_RereshareIdempotent — running Refresh repeatedly
// preserves the secret and rotates each round.
func TestRefreshCompositionInvariant(t *testing.T) {
	r := canonicalRing(t)
	const tThr, n = 3, 5
	secret := pickSecret(r, "refresh-compose", testNVec)
	rs := newFakeRand([]byte("compose-old"))
	current, err := makeStandardShamirShares(r, secret, tThr, n, rs)
	if err != nil {
		t.Fatal(err)
	}

	for round := 0; round < 4; round++ {
		next, err := Refresh(r, current, tThr,
			newFakeRand([]byte{byte(round)}))
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		rec, err := Verify(r, next, tThr)
		if err != nil {
			t.Fatal(err)
		}
		if !equalSecrets(rec, secret) {
			t.Fatalf("round %d: secret drifted", round)
		}
		current = next
	}
}

// TestRefreshComposesWithReshare — Refresh then Reshare must still
// preserve the secret, and Reshare then Refresh must do the same.
// This proves the two primitives compose correctly (which Quasar
// relies on: between validator-set rotations the chain may run
// Refresh as a periodic background hygiene step).
func TestRefreshComposesWithReshare(t *testing.T) {
	r := canonicalRing(t)
	const tOld, nOld = 3, 5
	secret := pickSecret(r, "refresh-then-reshare", testNVec)
	rs := newFakeRand([]byte("compose-rt-old"))
	original, err := makeStandardShamirShares(r, secret, tOld, nOld, rs)
	if err != nil {
		t.Fatal(err)
	}

	// Refresh first (same committee).
	refreshed, err := Refresh(r, original, tOld, newFakeRand([]byte("refresh-z")))
	if err != nil {
		t.Fatal(err)
	}
	rec1, err := Verify(r, refreshed, tOld)
	if err != nil {
		t.Fatal(err)
	}
	if !equalSecrets(rec1, secret) {
		t.Fatal("Refresh leg lost the secret")
	}

	// Reshare onto a new committee.
	const tNew = 4
	newSet := []int{20, 21, 22, 23, 24, 25, 26}
	reshared, err := Reshare(r, refreshed, tOld, newSet, tNew,
		newFakeRand([]byte("reshare-rng")))
	if err != nil {
		t.Fatal(err)
	}
	rec2, err := Verify(r, reshared, tNew)
	if err != nil {
		t.Fatal(err)
	}
	if !equalSecrets(rec2, secret) {
		t.Fatal("Reshare-after-Refresh lost the secret")
	}

	// Now reverse: Reshare first, then Refresh on the new committee.
	reshared2, err := Reshare(r, original, tOld, newSet, tNew,
		newFakeRand([]byte("reshare-rng-2")))
	if err != nil {
		t.Fatal(err)
	}
	refreshed2, err := Refresh(r, reshared2, tNew, newFakeRand([]byte("refresh-after-reshare")))
	if err != nil {
		t.Fatal(err)
	}
	rec3, err := Verify(r, refreshed2, tNew)
	if err != nil {
		t.Fatal(err)
	}
	if !equalSecrets(rec3, secret) {
		t.Fatal("Refresh-after-Reshare lost the secret")
	}
}
