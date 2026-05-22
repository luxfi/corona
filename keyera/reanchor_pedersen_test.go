// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keyera

import (
	"errors"
	"reflect"
	"testing"

	"github.com/luxfi/corona/dkg2"
	"github.com/luxfi/corona/hash"
	"github.com/luxfi/corona/sign"
)

// TestReanchorPedersen_RoundTrip — open a Pedersen-DKG era, rotate to a
// new committee with fresh keys via ReanchorPedersen, then drive the
// 2-round threshold-sign protocol under the new era's GroupKey. The
// resulting signature must verify under threshold.Verify.
//
// Acceptance criteria:
//   - The new era has a fresh GroupKey distinct from the prior era's.
//   - EraID monotonically increments.
//   - GenesisEpoch + State.Epoch advance to prev.State.Epoch + 1.
//   - The transcript is non-nil with a non-zero TranscriptHash.
//   - Threshold signing under the new shares verifies under the new
//     GroupKey.
//   - HashSuiteID is inherited from the prior era when unspecified.
func TestReanchorPedersen_RoundTrip(t *testing.T) {
	const thr, n = 3, 5
	v1 := []string{"v1", "v2", "v3", "v4", "v5"}

	era1, _, err := BootstrapPedersen(
		hash.NewCoronaSHA3(),
		thr, v1, 0, 1,
		deterministicRand("reanchor-pedersen-rt-era1"),
	)
	if err != nil {
		t.Fatalf("BootstrapPedersen era1: %v", err)
	}
	prevEpoch := era1.State.Epoch
	prevGK := era1.GroupKey
	prevEraID := era1.EraID
	prevSuiteID := era1.HashSuiteID

	v2 := []string{"v6", "v7", "v8", "v9", "v10"}
	era2, transcript, err := ReanchorPedersen(era1, thr, v2, 0,
		deterministicRand("reanchor-pedersen-rt-era2"))
	if err != nil {
		t.Fatalf("ReanchorPedersen: %v", err)
	}
	if era2 == nil || transcript == nil {
		t.Fatal("ReanchorPedersen returned nil era or transcript")
	}
	if era2.GroupKey == prevGK {
		t.Fatal("ReanchorPedersen returned same GroupKey pointer")
	}
	if era2.EraID != prevEraID+1 {
		t.Fatalf("EraID: want %d got %d", prevEraID+1, era2.EraID)
	}
	if era2.GenesisEpoch != prevEpoch+1 {
		t.Fatalf("GenesisEpoch: want %d got %d", prevEpoch+1, era2.GenesisEpoch)
	}
	if era2.State.Epoch != prevEpoch+1 {
		t.Fatalf("State.Epoch: want %d got %d", prevEpoch+1, era2.State.Epoch)
	}
	if era2.HashSuiteID != prevSuiteID {
		t.Fatalf("HashSuiteID inheritance: want %q got %q", prevSuiteID, era2.HashSuiteID)
	}
	if (transcript.TranscriptHash == [32]byte{}) {
		t.Fatal("transcript hash is zero")
	}
	if len(transcript.BetaSerialized) != n {
		t.Fatalf("transcript beta count: want %d got %d", n, len(transcript.BetaSerialized))
	}

	// Every new share is a real share (right dimension + GroupKey link).
	for vName, ks := range era2.State.Shares {
		if len(ks.SkShare) != sign.N {
			t.Fatalf("validator %s: SkShare dim %d, want %d", vName, len(ks.SkShare), sign.N)
		}
		if ks.GroupKey != era2.GroupKey {
			t.Fatalf("validator %s: GroupKey pointer mismatch", vName)
		}
	}

	// Sign + verify under the NEW era. This binds the contract: the
	// Pedersen-reanchored GroupKey accepts threshold-signed messages
	// under the new shares without any code change in the sign path.
	if !signAndVerify(t, era2, v2) {
		t.Fatal("post-ReanchorPedersen signature failed to verify under new GroupKey")
	}
}

// TestReanchorPedersen_NoMasterSecret — defense-in-depth: no party
// holds the new era's master secret s at any point during the
// rotation. The same structural argument that grounds
// BootstrapPedersen carries over because ReanchorPedersen routes
// through the identical dkg2/ + Path (a) path on the new era.
//
// Concrete checks:
//   - dkg2.DKGSession exposes no field named "masterSecret" /
//     "fullSecret" (lower-cased substring check).
//   - Every distinct pair of new-committee SkShares disagrees on at
//     least one coefficient (an orchestrator that wrote s into every
//     share slot would collide; we catch it here).
//   - Every new-committee Lambda is distinct (Lagrange weights cannot
//     collide for n ≥ 2 at distinct evaluation points).
//
// This is structural, not runtime — the Go runtime cannot prove
// absence of a value across all paths. The public-BFT-safe property
// is established by review + this structural check + the Pedersen-DKG
// security proof under MLWE on [A|B] (LP-073 §07).
func TestReanchorPedersen_NoMasterSecret(t *testing.T) {
	const thr, n = 3, 5
	v1 := []string{"a", "b", "c", "d", "e"}
	era1, _, err := BootstrapPedersen(
		hash.NewCoronaSHA3(),
		thr, v1, 0, 0,
		deterministicRand("reanchor-pedersen-noms-era1"),
	)
	if err != nil {
		t.Fatalf("BootstrapPedersen era1: %v", err)
	}

	v2 := []string{"f", "g", "h", "i", "j"}
	era2, _, err := ReanchorPedersen(era1, thr, v2, 0,
		deterministicRand("reanchor-pedersen-noms-era2"))
	if err != nil {
		t.Fatalf("ReanchorPedersen: %v", err)
	}

	// Structural assertion 1: dkg2.DKGSession exposes no master-secret
	// accessor field. This is shared with BootstrapPedersen but worth
	// re-asserting on the Reanchor path so a future regression on
	// either is caught.
	dkgType := reflect.TypeOf((*dkg2.DKGSession)(nil)).Elem()
	for i := 0; i < dkgType.NumField(); i++ {
		f := dkgType.Field(i)
		lower := lowercase(f.Name)
		if contains(lower, "mastersecret") || contains(lower, "fullsecret") {
			t.Fatalf("dkg2.DKGSession has a forbidden field %q — master-secret state leaks", f.Name)
		}
	}

	// Structural assertion 2: every new-committee pair of SkShares is
	// distinct. If an orchestrator regression wrote s into every share
	// slot, every pair would be byte-equal and we would catch it.
	for nameA, ksA := range era2.State.Shares {
		for nameB, ksB := range era2.State.Shares {
			if nameA >= nameB {
				continue
			}
			if sharesEqual(ksA, ksB) {
				t.Fatalf("validators %s and %s share identical secret bytes — orchestrator leaked master secret on Reanchor",
					nameA, nameB)
			}
		}
	}

	// Structural assertion 3: every new-committee Lambda is distinct.
	lambdaSeen := make(map[uint64]string)
	for vName, ks := range era2.State.Shares {
		key := ks.Lambda.Coeffs[0][0]
		if prev, ok := lambdaSeen[key]; ok && prev != vName {
			t.Fatalf("validators %s and %s share identical Lambda[0][0] — Lagrange weights degenerate on Reanchor",
				prev, vName)
		}
		lambdaSeen[key] = vName
	}
}

// TestReanchorPedersen_DishonestParty — one party broadcasts an
// inconsistent contribution during the Pedersen-DKG rounds. The
// Reanchor orchestrator must return ErrBootstrapPedersenAbort with an
// AbortEvidence naming the offending sender; the era and transcript
// are nil — the chain stays at the previous era.
//
// We drive the abort path through FinishBootstrapPedersen because the
// kernel ReanchorPedersen call always produces honest contributions.
// FinishBootstrapPedersen is the supported tampering entry; the
// behaviour is byte-identical to ReanchorPedersen on the abort path
// because ReanchorPedersen just delegates to BootstrapPedersen with
// era-id-and-epoch adjustments after the orchestrator returns.
func TestReanchorPedersen_DishonestParty(t *testing.T) {
	const thr, n = 3, 5
	validators := []string{"v1", "v2", "v3", "v4", "v5"}
	suite := hash.NewCoronaSHA3()

	dkgParams, err := dkg2.NewParams()
	if err != nil {
		t.Fatalf("dkg2.NewParams: %v", err)
	}
	sessions := make([]*dkg2.DKGSession, n)
	round1 := make([]*dkg2.Round1Output, n)
	rng := deterministicRand("reanchor-pedersen-dishonest")
	for i := 0; i < n; i++ {
		sess, err := dkg2.NewDKGSession(dkgParams, i, n, thr, suite)
		if err != nil {
			t.Fatalf("NewDKGSession[%d]: %v", i, err)
		}
		sessions[i] = sess
		seed := make([]byte, sign.KeySize)
		if _, err := rng.Read(seed); err != nil {
			t.Fatalf("rng.Read[%d]: %v", i, err)
		}
		out, err := sess.Round1WithSeed(seed)
		if err != nil {
			t.Fatalf("Round1WithSeed[%d]: %v", i, err)
		}
		round1[i] = out
	}

	// Tamper sender 4's share-to-recipient-1. Round2Identify from
	// recipient 1's perspective must name sender 4 as the bad actor.
	round1[4].Shares[1][0].Coeffs[0][0] ^= 0x42

	// The Reanchor abort path shares its semantics with the Bootstrap
	// abort path: FinishBootstrapPedersen is the kernel entrypoint and
	// the wrapping for era-id / epoch adjustments in ReanchorPedersen
	// occurs strictly AFTER a successful return.
	era, transcript, err := FinishBootstrapPedersen(
		suite, thr, validators, 0, 1,
		dkgParams, sessions, round1,
	)
	if era != nil || transcript != nil {
		t.Fatal("expected (nil, nil) on Reanchor abort")
	}
	if err == nil {
		t.Fatal("expected ErrBootstrapPedersenAbort, got nil")
	}
	if !errors.Is(err, ErrBootstrapPedersenAbort) {
		t.Fatalf("expected ErrBootstrapPedersenAbort wrapping, got %v", err)
	}
	ev := ExtractAbortEvidence(err)
	if ev == nil {
		t.Fatal("AbortEvidence nil after ExtractAbortEvidence")
	}
	if _, ok := ev.Disqualified[4]; !ok {
		t.Fatalf("expected sender 4 disqualified, disqualified=%v", ev.Disqualified)
	}
	if len(ev.Complaints) == 0 {
		t.Fatal("expected at least one Complaint in evidence")
	}
	if ev.Complaints[0].SenderID != 4 {
		t.Fatalf("complaint.SenderID: want 4 got %d", ev.Complaints[0].SenderID)
	}
	if ev.Complaints[0].Reason != dkg2.ComplaintBadDelivery {
		t.Fatalf("complaint.Reason: want bad-delivery got %v", ev.Complaints[0].Reason)
	}
	if ev.TranscriptHash == [32]byte{} {
		t.Fatal("AbortEvidence.TranscriptHash is zero")
	}
}

// TestReanchorTrustedDealer_LegacyAlias — confirm the legacy single-
// dealer alias still works (retained for HSM / TEE / publicly-
// observable foundation ceremonies). It is byte-equivalent to the
// pre-v0.7.4 Reanchor behaviour: same EraID / GenesisEpoch /
// State.Epoch progression and same shape KeyEra output.
//
// We assert byte-equivalence on bTilde across two calls with the same
// entropy stream — both runs consume identical bytes and traverse the
// identical Shamir kernel, so bTilde MUST agree.
func TestReanchorTrustedDealer_LegacyAlias(t *testing.T) {
	const thr, n = 3, 3
	era1, err := Bootstrap(thr, []string{"a", "b", "c"}, 0, 1,
		deterministicRand("reanchor-td-era1"))
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	prevEpoch := era1.State.Epoch
	prevGK := era1.GroupKey
	prevEraID := era1.EraID

	era2A, err := ReanchorTrustedDealer(era1, thr, []string{"x", "y", "z"}, 0,
		deterministicRand("reanchor-td-era2"))
	if err != nil {
		t.Fatalf("ReanchorTrustedDealer: %v", err)
	}
	era2B, err := ReanchorTrustedDealerWithSuite(era1, hash.NewCoronaSHA3(), thr,
		[]string{"x", "y", "z"}, 0, deterministicRand("reanchor-td-era2"))
	if err != nil {
		t.Fatalf("ReanchorTrustedDealerWithSuite: %v", err)
	}

	if era2A.GroupKey == prevGK {
		t.Fatal("ReanchorTrustedDealer returned same GroupKey pointer")
	}
	if era2A.EraID != prevEraID+1 {
		t.Fatalf("EraID: want %d got %d", prevEraID+1, era2A.EraID)
	}
	if era2A.GenesisEpoch != prevEpoch+1 {
		t.Fatalf("GenesisEpoch: want %d got %d", prevEpoch+1, era2A.GenesisEpoch)
	}
	if era2A.State.Epoch != prevEpoch+1 {
		t.Fatalf("State.Epoch: want %d got %d", prevEpoch+1, era2A.State.Epoch)
	}

	// Byte-equivalence: ReanchorTrustedDealer (default suite inherited
	// from Corona-SHA3) and ReanchorTrustedDealerWithSuite(Corona-SHA3)
	// MUST produce identical bTilde — both go through BootstrapWithSuite
	// on the same entropy stream.
	if !reflect.DeepEqual(era2A.GroupKey.BTilde, era2B.GroupKey.BTilde) {
		t.Fatal("ReanchorTrustedDealer diverges from ReanchorTrustedDealerWithSuite on bTilde — alias broken")
	}
	if !reflect.DeepEqual(era2A.State.Validators, era2B.State.Validators) {
		t.Fatal("ReanchorTrustedDealer diverges from ReanchorTrustedDealerWithSuite on validators")
	}

	// The legacy alias must still sign + verify under the new GroupKey.
	if !signAndVerify(t, era2A, []string{"x", "y", "z"}) {
		t.Fatal("ReanchorTrustedDealer GroupKey did not accept threshold-signed message")
	}
}
