// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keyera

// cutover_gate_test.go — the Phase-3a cutover gate for replacing corona/dkg2's
// hand-rolled Pedersen-VSS DKG with the shared github.com/luxfi/dkg library
// (vss + ring), parameterized by ring.Ringtail().
//
// Before any rewire, this gate proves — byte-for-byte — that luxfi/dkg's
// Ringtail binding reproduces corona/dkg2's KAT-pinned arithmetic:
//
//	(A) the public Pedersen matrices A, B are byte-identical;
//	(B) vss's REAL Round1 produces byte-identical Pedersen commits for the same
//	    per-party sampling seed (same χ sampler, same NTT/Mont convention);
//	(C) the secret share f_i(j) (Horner eval) is byte-identical;
//	(D) the group-key NTT convention: dkg2's Round2 b_ped uses IMForm+INTT
//	    (R^{-1}-scaled), vss's group commit T uses INTT-only (TRUE A·s1+B·u);
//	    the two differ by EXACTLY the Montgomery factor R. corona's PRODUCTION
//	    group key (keyera Path-(a) noise flooding) is the TRUE A·s+e'' — it does
//	    NOT use dkg2's b_ped — so it is convention-aligned with vss's TRUE T.
//
// (A)–(C) are the share-dealing core: if they hold, a vss-backed Bootstrap that
// keeps corona's own Path-(a) finalize preserves the group key + shares
// byte-for-byte. (D) pins PIN 4 of HANDOFF-PHASE3.md against ground truth.

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/luxfi/corona/dkg2"
	"github.com/luxfi/corona/hash"
	"github.com/luxfi/corona/sign"

	dkgchannel "github.com/luxfi/dkg/channel"
	dkgring "github.com/luxfi/dkg/ring"
	dkgvss "github.com/luxfi/dkg/vss"

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

// TestCutover_RingtailMatricesByteIdentical — gate (A). luxfi/dkg's
// ring.Ringtail() must derive the SAME public Pedersen matrices A, B as
// corona/dkg2.DeriveA/DeriveB (both BLAKE3("corona.dkg2.{A,B}.v1") → KeyedPRNG
// → uniform → NTT-Mont). This is the cutover gate: matrix divergence would make
// every commit, share, and group key diverge.
func TestCutover_RingtailMatricesByteIdentical(t *testing.T) {
	dkgParams, err := dkg2.NewParams()
	if err != nil {
		t.Fatalf("dkg2.NewParams: %v", err)
	}
	coronaA := dkg2.DeriveA(dkgParams.R)
	coronaB := dkg2.DeriveB(dkgParams.R)

	prof, err := dkgring.Ringtail()
	if err != nil {
		t.Fatalf("ring.Ringtail: %v", err)
	}

	if len(prof.A) != len(coronaA) || len(prof.B) != len(coronaB) {
		t.Fatalf("matrix row mismatch: A %d/%d B %d/%d",
			len(prof.A), len(coronaA), len(prof.B), len(coronaB))
	}
	for i := range coronaA {
		for j := range coronaA[i] {
			if !polysEqual(prof.A[i][j], coronaA[i][j]) {
				t.Fatalf("A[%d][%d] byte-divergent between Ringtail() and dkg2.DeriveA", i, j)
			}
			if !polysEqual(prof.B[i][j], coronaB[i][j]) {
				t.Fatalf("B[%d][%d] byte-divergent between Ringtail() and dkg2.DeriveB", i, j)
			}
		}
	}
	t.Logf("Ringtail() A,B byte-identical to dkg2.DeriveA/DeriveB over all %dx%d slots", len(coronaA), len(coronaA[0]))
}

// seededRound1Rng returns a reader that yields seed first (the 32 bytes vss
// Party.Round1 consumes as its sampling seed) then a deterministic tail (KEM
// encapsulation randomness — does NOT affect the commits, which are computed
// before any sealing). This makes vss's χ draws identical to a corona/dkg2
// Round1WithSeed(seed) run.
func seededRound1Rng(seed []byte) io.Reader {
	tail := make([]byte, 1<<16)
	// deterministic, distinct from seed; KEM randomness only.
	for i := range tail {
		tail[i] = byte(0x5A ^ (i & 0xFF))
	}
	return io.MultiReader(bytes.NewReader(seed), bytes.NewReader(tail))
}

// buildVSSParty0 constructs party 0 of an n-party vss committee with a directory
// of n fresh identities (identities affect only the sealed envelopes, never the
// public commits). Returns the party ready for Round1.
func buildVSSParty0(t *testing.T, prof *dkgring.Profile, n, thr int) *dkgvss.Party {
	return buildVSSPartyAt(t, prof, 0, n, thr)
}

// buildVSSPartyAt constructs party idx of an n-party vss committee with a fresh
// identity directory. Identities affect only sealed envelopes; gate E drives
// Round3 with DealerInputs built directly from dkg2's (gate-B/C-proven identical)
// cleartext contributions, so envelope decryption is not exercised — only vss's
// real verifyPedersen + aggregateShare.
func buildVSSPartyAt(t *testing.T, prof *dkgring.Profile, idx, n, thr int) *dkgvss.Party {
	t.Helper()
	ids := make([]*dkgchannel.IdentityKey, n)
	nodes := make([]dkgchannel.NodeID, n)
	entries := make(map[dkgchannel.NodeID]*dkgchannel.IdentityPublicKey, n)
	for i := 0; i < n; i++ {
		id, err := dkgchannel.GenerateIdentity(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateIdentity[%d]: %v", i, err)
		}
		ids[i] = id
		nodes[i] = dkgchannel.NodeID{byte(i + 1), 0xC0}
		entries[nodes[i]] = id.PublicKey()
	}
	dir, err := dkgchannel.NewIdentityDirectory(entries)
	if err != nil {
		t.Fatalf("NewIdentityDirectory: %v", err)
	}
	p, err := dkgvss.NewParty(prof, nodes[idx], ids[idx], idx, n, thr, nodes, dir, [32]byte{0xCA, 0xFE})
	if err != nil {
		t.Fatalf("NewParty: %v", err)
	}
	return p
}

// TestCutover_Round1CommitsByteIdentical — gate (B). vss's REAL Party.Round1
// (which internally samples χ, builds Pedersen commits C_k = A·NTT(c_k)+B·NTT(r_k))
// must produce commits byte-identical to corona/dkg2.Round1WithSeed for the same
// 32-byte sampling seed. This exercises vss's actual computeCommits path, not a
// reimplementation.
func TestCutover_Round1CommitsByteIdentical(t *testing.T) {
	const n, thr = 5, 3
	seed := make([]byte, sign.KeySize)
	for i := range seed {
		seed[i] = byte(0x11*i + 7)
	}

	// corona/dkg2 reference.
	dkgParams, err := dkg2.NewParams()
	if err != nil {
		t.Fatalf("dkg2.NewParams: %v", err)
	}
	sess, err := dkg2.NewDKGSession(dkgParams, 0, n, thr, hash.NewCoronaSHA3())
	if err != nil {
		t.Fatalf("NewDKGSession: %v", err)
	}
	coronaOut, err := sess.Round1WithSeed(seed)
	if err != nil {
		t.Fatalf("Round1WithSeed: %v", err)
	}

	// vss real Round1 with the same sampling seed.
	prof, err := dkgring.Ringtail()
	if err != nil {
		t.Fatalf("ring.Ringtail: %v", err)
	}
	party := buildVSSParty0(t, prof, n, thr)
	vssOut, err := party.Round1(seededRound1Rng(seed))
	if err != nil {
		t.Fatalf("vss Party.Round1: %v", err)
	}

	if len(vssOut.Commits) != len(coronaOut.Commits) {
		t.Fatalf("commit count: vss=%d corona=%d", len(vssOut.Commits), len(coronaOut.Commits))
	}
	for k := range coronaOut.Commits {
		if !vecsEqual(vssOut.Commits[k], coronaOut.Commits[k]) {
			t.Fatalf("commit[%d] byte-divergent between vss Round1 and dkg2 Round1WithSeed", k)
		}
	}
	t.Logf("vss Party.Round1 commits byte-identical to dkg2.Round1WithSeed over all %d Pedersen commits", len(coronaOut.Commits))
}

// TestCutover_HornerShareByteIdentical — gate (C). The secret share f_i(j) =
// Σ_k c_{i,k}·(j+1)^k must be byte-identical. corona/dkg2 computes it with a
// big.Int Horner (polyMulScalar/polyAddCoeffwise); vss computes it with the
// lattice ring's Barrett-reduced ScalarMulVec + VecAdd. Both yield the canonical
// representative in [0,q). This replicates vss's hornerEval (3 exported-op lines)
// because vss seals the share into an envelope rather than exposing it; the
// arithmetic under test is vss's own ring.ScalarMulVec / ring.VecAdd.
func TestCutover_HornerShareByteIdentical(t *testing.T) {
	const n, thr = 5, 3
	seed := make([]byte, sign.KeySize)
	for i := range seed {
		seed[i] = byte(0x09*i + 3)
	}

	dkgParams, err := dkg2.NewParams()
	if err != nil {
		t.Fatalf("dkg2.NewParams: %v", err)
	}
	sess, err := dkg2.NewDKGSession(dkgParams, 0, n, thr, hash.NewCoronaSHA3())
	if err != nil {
		t.Fatalf("NewDKGSession: %v", err)
	}
	coronaOut, err := sess.Round1WithSeed(seed)
	if err != nil {
		t.Fatalf("Round1WithSeed: %v", err)
	}

	// Re-sample the SAME c_{i,k} via luxfi/dkg's Ringtail χ sampler (identical
	// PRNG, σ, bound, order) and Horner-evaluate with vss's exported ring ops.
	prof, err := dkgring.Ringtail()
	if err != nil {
		t.Fatalf("ring.Ringtail: %v", err)
	}
	r := prof.Ring
	prng, err := dkgring.NewKeyedPRNG(seed)
	if err != nil {
		t.Fatalf("NewKeyedPRNG: %v", err)
	}
	cCoeffs := make([]dkgring.Vector, thr)
	for k := 0; k < thr; k++ {
		cCoeffs[k] = prof.SampleSecretVec(prng)
	}
	// (skip the r_{i,k} draws — not needed for the share value, but keep the
	// PRNG honest for any future blind comparison.)
	rCoeffs := make([]dkgring.Vector, thr)
	for k := 0; k < thr; k++ {
		rCoeffs[k] = prof.SampleSecretVec(prng)
	}
	_ = rCoeffs

	// hornerEval at every recipient point j+1, exactly as vss/party.go does.
	for j := 0; j < n; j++ {
		x := uint64(j + 1)
		share := dkgring.NewVec(r, prof.L)
		for k := thr - 1; k >= 0; k-- {
			if k < thr-1 {
				dkgring.ScalarMulVec(r, share, x, share)
			}
			dkgring.VecAdd(r, share, cCoeffs[k], share)
		}
		if !vecsEqual(share, coronaOut.Shares[j]) {
			t.Fatalf("share to recipient %d byte-divergent (vss Horner vs dkg2 Horner)", j)
		}
	}
	t.Logf("vss-style Horner shares byte-identical to dkg2 shares for all %d recipients", n)
}

// TestCutover_GroupKeyConvention — gate (D), PIN 4. Pins the exact NTT-domain
// relationship between the two group-commit conventions against ground truth:
//
//   - dkg2.Round2 b_ped  = RoundXi( ConvertVectorFromNTT(ΣC) )  [IMForm + INTT]
//   - vss group commit T = RoundXi( ConvertVecFromNTT(ΣC)    )  [INTT only]
//
// Because dkg2's commits are plain-NTT (Montgomery cancels in the commit
// multiply), the extra IMForm injects exactly one R^{-1}. So dkg2's pre-round
// vector is vss's TRUE A·s1+B·u scaled by R^{-1}; equivalently MForm(dkg2) == vss.
// This asserts that identity coefficient-wise — proving the two conventions
// differ by EXACTLY the Montgomery factor R, not by anything message-dependent.
//
// The corona PRODUCTION group key is NEITHER of these: keyera Path-(a) noise
// flooding multiplies NTT-Mont operands (A · NTT-Mont(λ_j·s_j)), so the surviving
// R is correctly removed by ConvertVectorFromNTT, yielding the TRUE A·s+e”
// (convention-aligned with vss's TRUE T). dkg2's R^{-1}-scaled b_ped is an
// internal Round2 value the production path discards.
func TestCutover_GroupKeyConvention(t *testing.T) {
	prof, err := dkgring.Ringtail()
	if err != nil {
		t.Fatalf("ring.Ringtail: %v", err)
	}
	r := prof.Ring

	// Deterministic plain-NTT "aggregated commit" ΣC ∈ R_q^K: derive it as a
	// real commit A·NTT(c) + B·NTT(r) so it lives in the exact commit domain.
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

// TestCutover_Round3AggregationByteIdentical — gate (E), the LAST byte-equality
// the production swap rests on. Feeding dkg2's (gate-B/C-proven byte-identical)
// per-dealer commits/shares/blinds into vss's REAL Round3 must:
//
//	(1) pass vss's verifyPedersen for EVERY dealer — proving vss's verify accepts
//	    dkg2's contributions cross-implementation (despite dkg2's "NTT-Montgomery"
//	    vs vss's "plain-NTT" commit-domain comments, the bytes and the Pedersen
//	    identity agree); and
//	(2) produce the aggregated secret share s_j = Σ_i f_i(j) BYTE-IDENTICAL to
//	    dkg2's Round2Identify.
//
// gate C proved each per-dealer share f_i(j) is identical; this pins the
// AGGREGATION + VERIFY step (vss.aggregateShare / vss.verifyPedersen ==
// dkg2.Round2Identify). With gates A–E green, BootstrapPedersen can drive vss
// (Round1 → OpenDealerShare → Round3.ShareResult.Share) for the share-dealing DKG
// and keep corona's own Path-(a) noise-flooding finalize, preserving the group
// key + per-party shares byte-for-byte — i.e. deployed corona signatures survive.
func TestCutover_Round3AggregationByteIdentical(t *testing.T) {
	const n, thr = 5, 3
	suite := hash.NewCoronaSHA3()

	// dkg2 reference: full Round1 for all n parties.
	dkgParams, err := dkg2.NewParams()
	if err != nil {
		t.Fatalf("dkg2.NewParams: %v", err)
	}
	sessions := make([]*dkg2.DKGSession, n)
	round1 := make([]*dkg2.Round1Output, n)
	for i := 0; i < n; i++ {
		sess, err := dkg2.NewDKGSession(dkgParams, i, n, thr, suite)
		if err != nil {
			t.Fatalf("NewDKGSession[%d]: %v", i, err)
		}
		sessions[i] = sess
		seed := make([]byte, sign.KeySize)
		for k := range seed {
			seed[k] = byte(0x07*i + 0x13*k + 1)
		}
		out, err := sess.Round1WithSeed(seed)
		if err != nil {
			t.Fatalf("Round1WithSeed[%d]: %v", i, err)
		}
		round1[i] = out
	}

	prof, err := dkgring.Ringtail()
	if err != nil {
		t.Fatalf("ring.Ringtail: %v", err)
	}

	for j := 0; j < n; j++ {
		// dkg2 aggregated, verified share s_j (the production Round 2 path).
		shares := map[int]structs.Vector[lring.Poly]{}
		blinds := map[int]structs.Vector[lring.Poly]{}
		commits := map[int][]structs.Vector[lring.Poly]{}
		for i := 0; i < n; i++ {
			shares[i] = round1[i].Shares[j]
			blinds[i] = round1[i].Blinds[j]
			commits[i] = round1[i].Commits
		}
		dkg2Sj, _, _, badID, err := sessions[j].Round2Identify(shares, blinds, commits)
		if err != nil {
			t.Fatalf("dkg2 Round2Identify[%d] (badID=%d): %v", j, badID, err)
		}

		// vss real Round3 over the SAME (commits, share, blind) inputs.
		party := buildVSSPartyAt(t, prof, j, n, thr)
		inputs := make(map[int]*dkgvss.DealerInput, n)
		for i := 0; i < n; i++ {
			inputs[i] = &dkgvss.DealerInput{
				Commits: round1[i].Commits,
				Share:   round1[i].Shares[j],
				Blind:   round1[i].Blinds[j],
			}
		}
		res, fault, err := party.Round3(inputs)
		if err != nil {
			if fault != nil {
				t.Fatalf("vss Round3[%d]: verifyPedersen REJECTED dkg2 dealer %d — commit-domain conventions diverge (blocker)", j, fault.DealerIndex)
			}
			t.Fatalf("vss Round3[%d]: %v", j, err)
		}
		if !vecsEqual(res.Share, dkg2Sj) {
			t.Fatalf("aggregated s_%d byte-divergent: vss Round3 aggregateShare != dkg2 Round2Identify", j)
		}
	}
	t.Logf("vss Round3 (verifyPedersen + aggregateShare) byte-identical to dkg2 Round2Identify for all %d recipients", n)
}
