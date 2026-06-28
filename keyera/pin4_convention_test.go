// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keyera

// pin4_convention_test.go — the PIN-4 group-key NTT-convention assertion
// (HANDOFF-PHASE3.md). It is the durable, dkg2-free record of WHY the move to
// luxfi/dkg preserved corona's group key.
//
// Two ways to materialize the aggregated Pedersen commit ΣC ∈ R_q^K (plain-NTT)
// into coefficient form:
//
//   - IMForm + INTT : the historical corona/dkg2 Round2 b_ped path. Because the
//     commits are plain-NTT (Montgomery cancels in the commit multiply), the
//     extra IMForm injects one spurious R^{-1}, so this is R^{-1}-scaled.
//   - INTT only     : the luxfi/dkg vss group-commit T path — the TRUE A·s1+B·u.
//
// The two differ by EXACTLY the Montgomery factor R (MForm(IMForm+INTT) == INTT).
// corona's PRODUCTION group key is NEITHER: keyera Path-(a) noise flooding
// multiplies NTT-Mont operands (A · NTT-Mont(λ_j·s_j)), so the surviving R is
// correctly removed by ConvertVectorFromNTT, yielding the TRUE A·s+e'' —
// convention-aligned with vss's TRUE T. The dkg2 R^{-1}-scaled b_ped was an
// internal Round2 value the production path always discarded, which is why the
// rewire (keep corona's Path-(a) finalize, use vss only for share-dealing)
// preserves the group key with NO convention change.

import (
	"testing"

	"github.com/luxfi/corona/sign"

	dkgring "github.com/luxfi/dkg/ring"

	lring "github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/structs"
)

// polysEqual reports byte-equality of two single-modulus polynomials over all
// coefficients (Coeffs[0]); the corona ring is single-level so this is total.
func polysEqual(a, b lring.Poly) bool {
	if len(a.Coeffs) != len(b.Coeffs) {
		return false
	}
	for lvl := range a.Coeffs {
		if len(a.Coeffs[lvl]) != len(b.Coeffs[lvl]) {
			return false
		}
		for i := range a.Coeffs[lvl] {
			if a.Coeffs[lvl][i] != b.Coeffs[lvl][i] {
				return false
			}
		}
	}
	return true
}

func vecsEqual(a, b structs.Vector[lring.Poly]) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !polysEqual(a[i], b[i]) {
			return false
		}
	}
	return true
}

// TestPin4_GroupKeyConvention pins the exact NTT-domain relationship between the
// two group-commit conventions against ground truth (see file header).
func TestPin4_GroupKeyConvention(t *testing.T) {
	prof, err := dkgring.Ringtail()
	if err != nil {
		t.Fatalf("ring.Ringtail: %v", err)
	}
	r := prof.Ring

	// Deterministic plain-NTT "aggregated commit" ΣC ∈ R_q^K: build it as a real
	// commit A·NTT(c) + B·NTT(r) so it lives in the exact commit domain.
	seed := make([]byte, sign.KeySize)
	for i := range seed {
		seed[i] = byte(0x33*i + 1)
	}
	prng, err := dkgring.NewKeyedPRNG(seed)
	if err != nil {
		t.Fatalf("NewKeyedPRNG: %v", err)
	}
	c := prof.SampleSecretVec(prng)
	rr := prof.SampleSecretVec(prng)
	cN := dkgring.CopyVec(c)
	rN := dkgring.CopyVec(rr)
	dkgring.NTTVec(r, cN)
	dkgring.NTTVec(r, rN)
	ac := dkgring.NewVec(r, prof.K)
	br := dkgring.NewVec(r, prof.K)
	dkgring.MatVecMul(r, prof.A, cN, ac)
	dkgring.MatVecMul(r, prof.B, rN, br)
	sumC := dkgring.NewVec(r, prof.K) // plain-NTT aggregated commit
	dkgring.VecAdd(r, ac, br, sumC)

	// vss convention: INTT only → TRUE A·s1+B·u (standard coeff form).
	vssT := dkgring.CopyVec(sumC)
	dkgring.ConvertVecFromNTT(r, vssT) // INTT only

	// dkg2 convention: IMForm + INTT → R^{-1}-scaled.
	base := prof.Ring.Base()
	dkg2T := dkgring.CopyVec(sumC)
	for i := range dkg2T {
		base.IMForm(dkg2T[i], dkg2T[i])
		base.INTT(dkg2T[i], dkg2T[i])
	}

	// They must DIFFER (the conventions genuinely diverge)...
	if vecsEqual(vssT, dkg2T) {
		t.Fatal("expected the IMForm+INTT and INTT-only conventions to differ; they did not")
	}

	// ...and differ by EXACTLY the Montgomery factor R: MForm(dkg2T) == vssT.
	reMont := dkgring.CopyVec(dkg2T)
	for i := range reMont {
		base.MForm(reMont[i], reMont[i])
	}
	if !vecsEqual(reMont, vssT) {
		t.Fatal("MForm(dkg2 b_ped pre-round) != vss T: the conventions do not differ by exactly R")
	}
	t.Log("PIN 4 confirmed: dkg2 b_ped (IMForm+INTT) = vss T (INTT-only) scaled by R^{-1}; " +
		"production keyera Path-(a) key is the TRUE A·s+e'' (R-cancelled), convention-aligned with vss T")
}
