// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package reshare

import (
	"bytes"
	"testing"
)

// The Refresh secret-preservation / composition tests that reconstruct the
// master secret (via the research-only reshare.Verify) live in
// refresh_research_test.go behind the `corona_research` build tag. This file
// keeps the Refresh production-behaviour tests that do NOT reconstruct.

// TestRefreshDeterminism — same RNG stream produces byte-identical
// refreshed shares. Foundation for the C++ KAT.
func TestRefreshDeterminism(t *testing.T) {
	r := canonicalRing(t)
	const tThr, n = 3, 5
	secret := pickSecret(r, "refresh-det", testNVec)
	rs := newFakeRand([]byte("refresh-det-old"))
	oldShares, err := makeStandardShamirShares(r, secret, tThr, n, rs)
	if err != nil {
		t.Fatal(err)
	}

	a, err := Refresh(r, oldShares, tThr, newFakeRand([]byte("refresh-det-z")))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Refresh(r, oldShares, tThr, newFakeRand([]byte("refresh-det-z")))
	if err != nil {
		t.Fatal(err)
	}
	for id := range oldShares {
		ah := uint64sToBytes(flattenShare(a[id]))
		bh := uint64sToBytes(flattenShare(b[id]))
		if !bytes.Equal(ah, bh) {
			t.Fatalf("party %d: non-deterministic Refresh output", id)
		}
	}
}

// TestRefreshThreshold1 — degenerate t=1 case: every share IS the
// secret. Refresh must be the identity (no zero-polynomial of degree
// 0 can be non-trivial while satisfying z(0) = 0).
func TestRefreshThreshold1(t *testing.T) {
	r := canonicalRing(t)
	const tThr, n = 1, 3
	secret := pickSecret(r, "refresh-t1", testNVec)
	// With t=1, every share equals secret directly (every party holds
	// the secret).
	shares := make(map[int]Share, n)
	for j := 1; j <= n; j++ {
		v := make(Share, testNVec)
		for p := 0; p < testNVec; p++ {
			v[p] = r.NewPoly()
			copy(v[p].Coeffs[0], secret[p].Coeffs[0])
		}
		shares[j] = v
	}

	out, err := Refresh(r, shares, tThr, newFakeRand([]byte("t1-rng")))
	if err != nil {
		t.Fatal(err)
	}
	for id, in := range shares {
		want := flattenShare(in)
		got := flattenShare(out[id])
		if !bytes.Equal(uint64sToBytes(want), uint64sToBytes(got)) {
			t.Fatalf("party %d: Refresh with t=1 should be identity", id)
		}
	}
}

// TestRefreshInvalidArgs — error paths for Refresh.
func TestRefreshInvalidArgs(t *testing.T) {
	r := canonicalRing(t)
	const tThr, n = 3, 5
	secret := pickSecret(r, "refresh-invalid", 2)
	rs := newFakeRand([]byte("refresh-invalid-rng"))
	good, err := makeStandardShamirShares(r, secret, tThr, n, rs)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		fn     func() error
		errMsg string
	}{
		{
			"threshold < 1",
			func() error {
				_, err := Refresh(r, good, 0, newFakeRand([]byte("r")))
				return err
			},
			"t_old must be >= 1",
		},
		{
			"empty shares",
			func() error {
				_, err := Refresh(r, map[int]Share{}, 1, newFakeRand([]byte("r")))
				return err
			},
			"no old shares",
		},
		{
			"threshold larger than committee",
			func() error {
				_, err := Refresh(r, good, 99, newFakeRand([]byte("r")))
				return err
			},
			"fewer than t_old shares",
		},
		{
			"zero ID",
			func() error {
				bad := map[int]Share{0: good[1]}
				_, err := Refresh(r, bad, 1, newFakeRand([]byte("r")))
				return err
			},
			"1-indexed",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.fn()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.errMsg)
			}
			if !bytes.Contains([]byte(err.Error()), []byte(tc.errMsg)) {
				t.Fatalf("expected error containing %q, got %q", tc.errMsg, err.Error())
			}
		})
	}
}
