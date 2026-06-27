// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package threshold

import (
	"crypto/rand"
	"testing"
)

// TestThresholdSubQuorumCannotForge pins the permissionless threshold-
// soundness invariant: a strict sub-quorum of the committee (a minority
// that omits at least one signer) CANNOT assemble a signature that
// verifies under the group public key.
//
// Why this holds at runtime: each party's Round-2 partial carries an
// additive PRF mask term (mask / maskPrime in sign.SignRound2). Those
// masks only telescope to zero when the partials are summed over the
// FULL signing set T. Drop any signer and the aggregate z retains an
// uncancelled, high-norm mask, so the L2-norm gate in sign.Verify
// (CheckL2Norm against Bsquare) rejects it. This is the runtime
// counterpart to the (t,n)-Shamir secrecy argument: fewer than the full
// quorum can neither interpolate s nor emit a low-norm signature.
//
// If a sub-quorum signature EVER verified, that would be a catastrophic
// forgery break (a minority producing valid finality certs), so this
// test is an adversarial negative, not a smoke test.
func TestThresholdSubQuorumCannotForge(t *testing.T) {
	const tt, n = 3, 5
	shares, gk, err := GenerateKeysTrustedDealer(tt, n, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeysTrustedDealer(%d,%d): %v", tt, n, err)
	}

	signers := make([]*Signer, n)
	for i, share := range shares {
		signers[i] = NewSigner(share)
	}
	signerIDs := make([]int, n)
	for i := range signerIDs {
		signerIDs[i] = i
	}

	const sid = 1
	prfKey := make([]byte, 32)
	if _, err := rand.Read(prfKey); err != nil {
		t.Fatal(err)
	}
	message := "corona minority-soundness test"

	// Round 1 — every committee member participates so masks are set up
	// over the full set T (the honest protocol).
	r1 := make(map[int]*Round1Data, n)
	for _, s := range signers {
		d := s.Round1(sid, prfKey, signerIDs)
		r1[d.PartyID] = d
	}

	// Round 2 — every committee member emits its z partial.
	r2 := make(map[int]*Round2Data, n)
	for _, s := range signers {
		d, err := s.Round2(sid, message, prfKey, signerIDs, r1)
		if err != nil {
			t.Fatalf("Round2 party %d: %v", s.share.Index, err)
		}
		r2[d.PartyID] = d
	}

	// Positive control: the FULL quorum produces a verifying signature.
	fullSig, err := signers[0].Finalize(r2)
	if err != nil {
		t.Fatalf("Finalize (full quorum): %v", err)
	}
	if !Verify(gk, message, fullSig) {
		t.Fatal("full-quorum honest signature was rejected — test setup is wrong")
	}

	// Adversarial negative: a minority of size t-1 = 2 (parties {0,1})
	// attempts to finalize using only its own partials. The aggregate z
	// is missing n-(t-1)=3 mask-cancelling terms.
	minority := map[int]*Round2Data{
		0: r2[0],
		1: r2[1],
	}
	if len(minority) >= n {
		t.Fatalf("minority set not a strict subset: |minority|=%d n=%d", len(minority), n)
	}
	forged, err := signers[0].Finalize(minority)
	if err != nil {
		// A hard error here is also an acceptable rejection of the minority
		// attempt; the invariant (no valid sub-quorum signature) still holds.
		return
	}
	if Verify(gk, message, forged) {
		t.Fatalf("CRITICAL: a %d-of-%d sub-quorum produced a signature that "+
			"VERIFIED under the group key — threshold soundness is broken "+
			"(minority forgery)", len(minority), n)
	}
}
