// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package threshold

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/luxfi/corona/sign"
)

// TestE2EThresholdVariants exercises the threshold ceremony at the four
// committee sizes called out in the v0.7.0 work plan: (3,2), (5,3),
// (7,4), (10,7). All four must produce a valid signature.
//
// This is the canonical e2e suite mirroring Pulsar's reshare_test variants.
func TestE2EThresholdVariants(t *testing.T) {
	cases := []struct {
		t, n int
	}{
		{2, 3},
		{3, 5},
		{4, 7},
		{7, 10},
	}

	for _, tc := range cases {
		tc := tc
		t.Run("", func(t *testing.T) {
			shares, gk, err := GenerateKeysTrustedDealer(tc.t, tc.n, rand.Reader)
			if err != nil {
				t.Fatalf("(%d,%d) GenerateKeys: %v", tc.t, tc.n, err)
			}
			if len(shares) != tc.n {
				t.Fatalf("(%d,%d) wanted %d shares, got %d",
					tc.t, tc.n, tc.n, len(shares))
			}
			signers := make([]*Signer, tc.n)
			for i, share := range shares {
				signers[i] = NewSigner(share)
			}
			signerIDs := make([]int, tc.n)
			for i := range signerIDs {
				signerIDs[i] = i
			}
			const sid = 1
			prfKey := make([]byte, 32)
			if _, err := rand.Read(prfKey); err != nil {
				t.Fatal(err)
			}
			message := "corona e2e variants test"

			// Round 1.
			r1 := make(map[int]*Round1Data, tc.n)
			for _, s := range signers {
				d, err := s.Round1(sid, prfKey, signerIDs)
				if err != nil {
					t.Fatalf("(%d,%d) Round1 party %d: %v",
						tc.t, tc.n, s.share.Index, err)
				}
				r1[d.PartyID] = d
			}
			// Round 2.
			r2 := make(map[int]*Round2Data, tc.n)
			for _, s := range signers {
				d, err := s.Round2(sid, message, prfKey, signerIDs, r1)
				if err != nil {
					t.Fatalf("(%d,%d) Round2 party %d: %v",
						tc.t, tc.n, s.share.Index, err)
				}
				r2[d.PartyID] = d
			}
			// Finalize + Verify.
			sig, err := signers[0].Finalize(r2)
			if err != nil {
				t.Fatalf("(%d,%d) Finalize: %v", tc.t, tc.n, err)
			}
			if !Verify(gk, message, sig) {
				t.Fatalf("(%d,%d) Verify rejected an honest signature",
					tc.t, tc.n)
			}
		})
	}
}

// TestE2EKATReplayDeterminism asserts that running the same protocol
// inputs twice captures the post-hedging nonce contract:
//
//   - With the DEFAULT crypto/rand nonce source (production), two signings
//     on the same key set, sid, prfKey and message yield DISTINCT
//     signature bytes — fresh per-signature nonces, so R is never reused
//     even when sid repeats. This is the property that durably closes the
//     CRIT-1 nonce-reuse leak.
//   - With a PINNED deterministic nonce source (the KAT/oracle seam), two
//     signings yield BYTE-IDENTICAL signatures — reproducibility for the
//     cross-runtime KAT vectors.
func TestE2EKATReplayDeterminism(t *testing.T) {
	seed := [32]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	}
	const message = "corona KAT replay determinism"

	// pinNonce: when true, pin each signer to a deterministic, per-party
	// salt source so the run is byte-reproducible; otherwise leave the
	// default crypto/rand (hedged production path).
	runSign := func(shares []*KeyShare, pinNonce bool) []byte {
		signers := make([]*Signer, len(shares))
		for i, share := range shares {
			signers[i] = NewSigner(share)
			if pinNonce {
				signers[i].SetNonceRand(sign.DeterministicNonceSource(seed[:], i))
			}
		}
		signerIDs := make([]int, len(shares))
		for i := range signerIDs {
			signerIDs[i] = i
		}
		const sid = 1
		prfKey := seed[:]

		r1 := make(map[int]*Round1Data, len(shares))
		for _, s := range signers {
			d, err := s.Round1(sid, prfKey, signerIDs)
			if err != nil {
				t.Fatalf("Round1: %v", err)
			}
			r1[d.PartyID] = d
		}
		r2 := make(map[int]*Round2Data, len(shares))
		for _, s := range signers {
			d, err := s.Round2(sid, message, prfKey, signerIDs, r1)
			if err != nil {
				t.Fatalf("Round2: %v", err)
			}
			r2[d.PartyID] = d
		}
		sig, err := signers[0].Finalize(r2)
		if err != nil {
			t.Fatalf("Finalize: %v", err)
		}
		if !Verify(&GroupKey{A: shares[0].GroupKey.A, BTilde: shares[0].GroupKey.BTilde, Params: shares[0].GroupKey.Params}, message, sig) {
			t.Fatal("signature must verify")
		}
		b, err := sig.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary: %v", err)
		}
		return b
	}

	shares, _, err := GenerateKeysTrustedDealer(2, 3, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}

	// Hedged production path: two runs MUST differ (fresh nonces) yet both
	// verify. Distinct bytes here is the direct, observable evidence that
	// R is not reused across signatures of the same (share, sid).
	if bytes.Equal(runSign(shares, false), runSign(shares, false)) {
		t.Fatal("hedged signing produced byte-identical signatures across two runs: nonce not fresh (CRIT-1 reuse risk)")
	}

	// Pinned deterministic path: two runs MUST be byte-identical
	// (KAT reproducibility).
	if !bytes.Equal(runSign(shares, true), runSign(shares, true)) {
		t.Fatal("pinned-nonce signing not byte-reproducible across two runs")
	}
}
