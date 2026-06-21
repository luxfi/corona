// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package reshare

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"math/big"
	"testing"

	"github.com/luxfi/corona/sign"

	"github.com/luxfi/lattice/v7/ring"
)

const (
	testLogN = 8
	testQ    = sign.Q
	testNVec = 3
)

// fakeRand is a deterministic PRNG built from a SHA-256 counter mode.
// It is used to make every test reproducible (and therefore amenable to
// the KAT oracle path).
type fakeRand struct {
	seed []byte
	ctr  uint64
	buf  []byte
}

func newFakeRand(seed []byte) *fakeRand {
	return &fakeRand{seed: append([]byte{}, seed...)}
}

func (f *fakeRand) Read(p []byte) (int, error) {
	written := 0
	for written < len(p) {
		if len(f.buf) == 0 {
			h := sha256.New()
			h.Write([]byte("reshare-test-rand:"))
			h.Write(f.seed)
			var ctrBuf [8]byte
			binary.BigEndian.PutUint64(ctrBuf[:], f.ctr)
			h.Write(ctrBuf[:])
			f.buf = h.Sum(nil)
			f.ctr++
		}
		n := copy(p[written:], f.buf)
		f.buf = f.buf[n:]
		written += n
	}
	return written, nil
}

var _ io.Reader = (*fakeRand)(nil)

// canonicalRing returns the production R_q ring used by sign.Gen.
func canonicalRing(t *testing.T) *ring.Ring {
	t.Helper()
	r, err := ring.NewRing(1<<testLogN, []uint64{testQ})
	if err != nil {
		t.Fatalf("NewRing: %v", err)
	}
	return r
}

// makeStandardShamirShares manually creates (t, n)-Shamir shares of a
// chosen secret vector s ∈ R_q^{nVec}, using the standard polynomial
// evaluation form share_i = P(i) for i ∈ {1,..,n}. We do this directly
// here (rather than calling primitives.ShamirSecretSharingGeneral) so
// the test does NOT depend on production code that we are about to
// reshare — keeps the test independent.
func makeStandardShamirShares(
	r *ring.Ring,
	secret []ring.Poly,
	tThreshold, n int,
	rs io.Reader,
) (map[int]Share, error) {
	q := r.Modulus()
	N := r.N()
	nVec := len(secret)

	shares := make(map[int]Share, n)
	for j := 1; j <= n; j++ {
		v := make(Share, nVec)
		for p := 0; p < nVec; p++ {
			v[p] = r.NewPoly()
		}
		shares[j] = v
	}

	for p := 0; p < nVec; p++ {
		for k := 0; k < N; k++ {
			coeffs := make([]*big.Int, tThreshold)
			coeffs[0] = new(big.Int).SetUint64(secret[p].Coeffs[0][k])
			for d := 1; d < tThreshold; d++ {
				coeffs[d] = sampleModQ(rs, q)
			}
			for j := 1; j <= n; j++ {
				xj := big.NewInt(int64(j))
				acc := new(big.Int).Set(coeffs[tThreshold-1])
				for d := tThreshold - 2; d >= 0; d-- {
					acc.Mul(acc, xj)
					acc.Add(acc, coeffs[d])
					acc.Mod(acc, q)
				}
				shares[j][p].Coeffs[0][k] = acc.Uint64()
			}
		}
	}
	return shares, nil
}

// pickSecret returns a deterministic secret vector derived from `seed`.
func pickSecret(r *ring.Ring, seed string, nVec int) []ring.Poly {
	q := r.Modulus()
	N := r.N()
	rs := newFakeRand([]byte("secret:" + seed))
	out := make([]ring.Poly, nVec)
	for p := 0; p < nVec; p++ {
		out[p] = r.NewPoly()
		for k := 0; k < N; k++ {
			out[p].Coeffs[0][k] = sampleModQ(rs, q).Uint64()
		}
	}
	return out
}

// equalSecrets asserts that two []ring.Poly are identical on level 0.
func equalSecrets(a, b []ring.Poly) bool {
	if len(a) != len(b) {
		return false
	}
	for p := range a {
		if !bytes.Equal(uint64sToBytes(a[p].Coeffs[0]), uint64sToBytes(b[p].Coeffs[0])) {
			return false
		}
	}
	return true
}

func uint64sToBytes(u []uint64) []byte {
	buf := make([]byte, 8*len(u))
	for i, v := range u {
		binary.BigEndian.PutUint64(buf[i*8:], v)
	}
	return buf
}

// The Reshare/Refresh secret-preservation tests that reconstruct the master
// secret (via the research-only reshare.Verify) live in
// reshare_research_test.go behind the `corona_research` build tag. This file
// keeps the production-behaviour tests that do NOT reconstruct (determinism,
// argument validation, t=1 identity) plus the shared test helpers.

// TestReshareDeterminism — given the same RNG state, Reshare emits
// byte-identical new shares. This is the foundation for the C++
// byte-equal test.
func TestReshareDeterminism(t *testing.T) {
	r := canonicalRing(t)

	tOld, nOld := 3, 5
	secret := pickSecret(r, "determinism", testNVec)
	oldRng := newFakeRand([]byte("det-old"))
	oldShares, err := makeStandardShamirShares(r, secret, tOld, nOld, oldRng)
	if err != nil {
		t.Fatal(err)
	}

	tNew := 3
	newSet := []int{30, 31, 32, 33, 34}

	a, err := Reshare(r, oldShares, tOld, newSet, tNew, newFakeRand([]byte("det-reshare")))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Reshare(r, oldShares, tOld, newSet, tNew, newFakeRand([]byte("det-reshare")))
	if err != nil {
		t.Fatal(err)
	}
	for _, j := range newSet {
		ah := uint64sToBytes(flattenShare(a[j]))
		bh := uint64sToBytes(flattenShare(b[j]))
		if !bytes.Equal(ah, bh) {
			t.Fatalf("party %d: non-deterministic Reshare output", j)
		}
	}
}

func flattenShare(s Share) []uint64 {
	var out []uint64
	for _, poly := range s {
		out = append(out, poly.Coeffs[0]...)
	}
	return out
}

// TestReshareInvalidArgs — error paths.
func TestReshareInvalidArgs(t *testing.T) {
	r := canonicalRing(t)
	tOld, nOld := 2, 3
	secret := pickSecret(r, "invalid", 2)
	rs := newFakeRand([]byte("invalid-rng"))
	oldShares, err := makeStandardShamirShares(r, secret, tOld, nOld, rs)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		fn     func() error
		errMsg string
	}{
		{
			"tOld < 1",
			func() error {
				_, err := Reshare(r, oldShares, 0, []int{10, 11}, 2, newFakeRand([]byte("r")))
				return err
			},
			"t_old must be >= 1",
		},
		{
			"tNew < 1",
			func() error {
				_, err := Reshare(r, oldShares, 2, []int{10, 11}, 0, newFakeRand([]byte("r")))
				return err
			},
			"t_new must be >= 1",
		},
		{
			"empty old",
			func() error {
				_, err := Reshare(r, map[int]Share{}, 1, []int{10}, 1, newFakeRand([]byte("r")))
				return err
			},
			"no old shares",
		},
		{
			"empty new",
			func() error {
				_, err := Reshare(r, oldShares, 2, nil, 1, newFakeRand([]byte("r")))
				return err
			},
			"empty new committee",
		},
		{
			"tOld too large",
			func() error {
				_, err := Reshare(r, oldShares, 99, []int{10, 11}, 2, newFakeRand([]byte("r")))
				return err
			},
			"fewer than t_old shares",
		},
		{
			"zero ID in new set",
			func() error {
				_, err := Reshare(r, oldShares, 2, []int{0, 1}, 2, newFakeRand([]byte("r")))
				return err
			},
			"1-indexed",
		},
		{
			"duplicate ID in new set",
			func() error {
				_, err := Reshare(r, oldShares, 2, []int{10, 10}, 2, newFakeRand([]byte("r")))
				return err
			},
			"duplicate",
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

// TestRefreshThresholdOne — degenerate case. With t = 1 every share IS
// the secret, so Refresh must be the identity (no degree-≥1 fresh terms
// can be added without changing the secret).
func TestRefreshThresholdOne(t *testing.T) {
	r := canonicalRing(t)

	// Build "shares" of t=1 manually: every party's share equals the
	// secret itself.
	secret := pickSecret(r, "refresh-t1", 1)
	shares := make(map[int]Share, 3)
	for j := 1; j <= 3; j++ {
		v := make(Share, 1)
		v[0] = r.NewPoly()
		copy(v[0].Coeffs[0], secret[0].Coeffs[0])
		shares[j] = v
	}

	refreshed, err := Refresh(r, shares, 1,
		newFakeRand([]byte("any-seed")))
	if err != nil {
		t.Fatal(err)
	}
	for j, sh := range refreshed {
		if !equalSecrets([]ring.Poly(sh), []ring.Poly(shares[j])) {
			t.Fatalf("Refresh(t=1) was not the identity for party %d", j)
		}
	}
}
