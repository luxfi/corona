// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package reshare

import (
	"testing"

	"github.com/luxfi/corona/sign"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/structs"
)

// runRoundsAndVerify drives the production 2-round Corona sign protocol for a
// committee and checks the aggregate signature with sign.Verify. It is shared
// test plumbing for both the default-build and research-tagged integration
// tests; it reconstructs no secret (the signature is the protocol's public
// output), so it lives in this untagged file.
func runRoundsAndVerify(
	t *testing.T,
	label string,
	r *ring.Ring, rXi *ring.Ring, rNu *ring.Ring,
	A structs.Matrix[ring.Poly], bTilde structs.Vector[ring.Poly],
	parties []*sign.Party, signSet []int,
) bool {
	t.Helper()

	const sid = 1
	prfKey := []byte("integration-test-prfkey-32-bytes")
	mu := "test-message-" + label

	// Round 1.
	D := make(map[int]structs.Matrix[ring.Poly], len(parties))
	macs := make(map[int]map[int][]byte, len(parties))
	for _, p := range parties {
		Di, MAi, err := p.SignRound1(A, sid, prfKey, signSet)
		if err != nil {
			t.Fatalf("SignRound1 party %d (%s): %v", p.ID, label, err)
		}
		D[p.ID] = Di
		macs[p.ID] = MAi
	}

	// Round 2 preprocess + Round 2.
	Z := make(map[int]structs.Vector[ring.Poly], len(parties))
	var DSum structs.Matrix[ring.Poly]
	var hash []byte
	for _, p := range parties {
		ok, ds, h := p.SignRound2Preprocess(A, bTilde, D, macs, sid, signSet)
		if !ok {
			t.Errorf("%s: SignRound2Preprocess failed for party %d", label, p.ID)
			return false
		}
		if DSum == nil {
			DSum = ds
			hash = h
		}
		zi := p.SignRound2(A, bTilde, DSum, sid, mu, signSet, prfKey, hash)
		Z[p.ID] = zi
	}

	// Finalize.
	c, zSum, delta := parties[0].SignFinalize(Z, A, bTilde)
	ok := sign.Verify(r, rXi, rNu, zSum, A, mu, bTilde, c, delta)
	if !ok {
		t.Errorf("%s: signature failed to verify", label)
		return false
	}
	t.Logf("%s: signature verified", label)
	return true
}
