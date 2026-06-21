// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package sign

import (
	"bytes"
	"io"
	"math/big"
	"testing"

	"github.com/luxfi/corona/hash"
	"github.com/luxfi/corona/primitives"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/sampling"
	"github.com/luxfi/lattice/v7/utils/structs"
)

// zeroReader yields an unlimited stream of 0x00 — a degenerate
// randomness source, used to drive SignRound1's fail-closed guard.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// shortReader yields exactly n zero bytes total then EOFs, modelling a
// randomness source that cannot satisfy the 32-byte salt draw.
type shortReader struct{ n int }

func (s *shortReader) Read(p []byte) (int, error) {
	if s.n <= 0 {
		return 0, io.EOF
	}
	k := min(len(p), s.n)
	for i := 0; i < k; i++ {
		p[i] = 0
	}
	s.n -= k
	return k, nil
}

// newReuseTestParty builds one fully-keyed signing Party (index 0 of a
// K=3 group) via the real Gen ceremony, ready to call SignRound1.
func newReuseTestParty(t *testing.T) (*Party, structs.Matrix[ring.Poly], []int) {
	t.Helper()
	K = 3
	Threshold = K
	t.Cleanup(func() { K = 0; Threshold = 0 })

	r, err := ring.NewRing(1<<LogN, []uint64{Q})
	if err != nil {
		t.Fatal(err)
	}
	rXi, _ := ring.NewRing(1<<LogN, []uint64{QXi})
	rNu, _ := ring.NewRing(1<<LogN, []uint64{QNu})

	randomKey := make([]byte, KeySize)
	prng, _ := sampling.NewKeyedPRNG(randomKey)
	uniformSampler := ring.NewUniformSampler(prng, r)

	p, _ := sampling.NewKeyedPRNG(randomKey)
	us := ring.NewUniformSampler(p, r)
	party := NewPartyWithSuite(0, r, rXi, rNu, us, hash.NewCoronaSHA3())

	T := make([]int, K)
	for i := 0; i < K; i++ {
		T[i] = i
	}
	lagrange := primitives.ComputeLagrangeCoefficients(r, T, big.NewInt(int64(Q)))
	A, skShares, seeds, macKeys, _ := Gen(r, rXi, uniformSampler, randomKey, lagrange)
	party.SkShare = skShares[0]
	party.Seed = seeds
	party.MACKeys = macKeys[0]
	return party, A, T
}

// dMatrixBytes serializes a D matrix to canonical wire bytes for
// equality comparison. D = A·R + E, so a change in the Round-1 nonce R
// is observable as a change in these bytes.
func dMatrixBytes(t *testing.T, D structs.Matrix[ring.Poly]) []byte {
	t.Helper()
	var buf bytes.Buffer
	if _, err := D.WriteTo(&buf); err != nil {
		t.Fatalf("D.WriteTo: %v", err)
	}
	return buf.Bytes()
}

// TestSignRound1_NonceFreshAcrossReusedSession is the CRIT-1 regression:
// two SignRound1 calls with the SAME skShare and the SAME sid MUST NOT
// produce the same Round-1 commitment D (hence not the same nonce R),
// because the kernel hedges the nonce key with fresh crypto/rand. If they
// ever collide, the R-reuse leak (z_sum − Σ s_i·λ_i·c)·u^{-1} = R reopens.
func TestSignRound1_NonceFreshAcrossReusedSession(t *testing.T) {
	party, A, T := newReuseTestParty(t)
	const sid = 1 // deliberately reuse the SAME session id both times.

	d1, _, err := party.SignRound1(A, sid, []byte("prf-key-32-bytes-aaaaaaaaaaaaaaa"), T)
	if err != nil {
		t.Fatalf("SignRound1 #1: %v", err)
	}
	d2, _, err := party.SignRound1(A, sid, []byte("prf-key-32-bytes-aaaaaaaaaaaaaaa"), T)
	if err != nil {
		t.Fatalf("SignRound1 #2: %v", err)
	}

	if bytes.Equal(dMatrixBytes(t, d1), dMatrixBytes(t, d2)) {
		t.Fatal("two SignRound1 calls with the same (skShare, sid) produced " +
			"byte-identical D: nonce R was reused — CRIT-1 reuse leak reopened")
	}
}

// TestSignRound1_DeterministicWhenNoncePinned proves the KAT seam: with a
// pinned deterministic nonce source, two SignRound1 calls with identical
// inputs reproduce the same D byte-for-byte.
func TestSignRound1_DeterministicWhenNoncePinned(t *testing.T) {
	seed := bytes.Repeat([]byte{0xA5}, 32)

	run := func() []byte {
		party, A, T := newReuseTestParty(t)
		party.Rand = DeterministicNonceSource(seed, party.ID)
		d, _, err := party.SignRound1(A, 1, []byte("prf-key-32-bytes-aaaaaaaaaaaaaaa"), T)
		if err != nil {
			t.Fatalf("SignRound1: %v", err)
		}
		return dMatrixBytes(t, d)
	}

	if !bytes.Equal(run(), run()) {
		t.Fatal("pinned-nonce SignRound1 not byte-reproducible across runs")
	}
}

// TestSignRound1_FailClosedOnDegenerateNonce asserts the fail-closed
// precondition guard: a randomness source that yields an all-zero salt
// (forfeiting nonce freshness) is rejected with ErrDegenerateSession, and
// a source that cannot supply 32 bytes surfaces the read error. The kernel
// MUST refuse to sign rather than proceed with a degraded nonce.
func TestSignRound1_FailClosedOnDegenerateNonce(t *testing.T) {
	t.Run("zero-salt rejected", func(t *testing.T) {
		party, A, T := newReuseTestParty(t)
		party.Rand = zeroReader{}
		_, _, err := party.SignRound1(A, 1, []byte("prf-key-32-bytes-aaaaaaaaaaaaaaa"), T)
		if err != ErrDegenerateSession {
			t.Fatalf("want ErrDegenerateSession on zero salt, got %v", err)
		}
	})

	t.Run("short randomness surfaces read error", func(t *testing.T) {
		party, A, T := newReuseTestParty(t)
		party.Rand = &shortReader{n: 4} // < SessionIDSize (32).
		_, _, err := party.SignRound1(A, 1, []byte("prf-key-32-bytes-aaaaaaaaaaaaaaa"), T)
		if err == nil {
			t.Fatal("want a read error when the nonce source is short, got nil")
		}
		if err == ErrDegenerateSession {
			t.Fatal("short read should surface io error, not be masked as ErrDegenerateSession")
		}
	})
}
