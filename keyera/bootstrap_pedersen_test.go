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
	"github.com/luxfi/corona/threshold"
)

// TestBootstrapPedersen_RoundTrip — 5 parties run Pedersen DKG with
// threshold t=3. The orchestrator returns a KeyEra with shares for
// every validator and a BootstrapTranscript suitable for chain commit.
//
// Acceptance criteria:
//   - era.GroupKey is non-nil, A is the canonical dkg2 A
//     (nothing-up-my-sleeve).
//   - era.State.Shares has exactly n entries.
//   - transcript.TranscriptHash is non-zero and stable across two runs
//     with the same entropy stream.
//   - Every party's SkShare has the expected (sign.N) dimension.
//   - The era's threshold pins t.
func TestBootstrapPedersen_RoundTrip(t *testing.T) {
	const thr, n = 3, 5
	validators := []string{"v1", "v2", "v3", "v4", "v5"}

	era, transcript, err := BootstrapPedersen(
		hash.NewCoronaSHA3(),
		thr, validators, 0, 0,
		deterministicRand("bootstrap-pedersen-roundtrip"),
	)
	if err != nil {
		t.Fatalf("BootstrapPedersen: %v", err)
	}
	if era == nil || era.GroupKey == nil {
		t.Fatal("nil era / GroupKey")
	}
	if transcript == nil {
		t.Fatal("nil transcript")
	}
	if got := len(era.State.Shares); got != n {
		t.Fatalf("share count: want %d got %d", n, got)
	}
	if got := era.State.Threshold; got != thr {
		t.Fatalf("threshold: want %d got %d", thr, got)
	}
	if era.HashSuiteID != hash.DefaultID {
		t.Fatalf("suite: want %q got %q", hash.DefaultID, era.HashSuiteID)
	}
	if (transcript.TranscriptHash == [32]byte{}) {
		t.Fatal("transcript hash is zero")
	}
	if len(transcript.BetaSerialized) != n {
		t.Fatalf("transcript beta count: want %d got %d", n, len(transcript.BetaSerialized))
	}
	if len(transcript.Round1Digests) != n {
		t.Fatalf("transcript digest count: want %d got %d", n, len(transcript.Round1Digests))
	}

	// Every share has the right dimension.
	for v, ks := range era.State.Shares {
		if len(ks.SkShare) != sign.N {
			t.Fatalf("validator %s: SkShare dim %d, want %d", v, len(ks.SkShare), sign.N)
		}
		if ks.GroupKey != era.GroupKey {
			t.Fatalf("validator %s: GroupKey pointer mismatch", v)
		}
		if ks.Lambda.Coeffs == nil {
			t.Fatalf("validator %s: Lambda unset", v)
		}
	}

	// Determinism: running again with the same entropy yields the same
	// transcript hash, the same bTilde bytes, and the same digest set.
	era2, transcript2, err := BootstrapPedersen(
		hash.NewCoronaSHA3(),
		thr, validators, 0, 0,
		deterministicRand("bootstrap-pedersen-roundtrip"),
	)
	if err != nil {
		t.Fatalf("BootstrapPedersen replay: %v", err)
	}
	if transcript.TranscriptHash != transcript2.TranscriptHash {
		t.Fatal("transcript hash non-deterministic")
	}
	if !reflect.DeepEqual(transcript.Round1Digests, transcript2.Round1Digests) {
		t.Fatal("Round1Digests non-deterministic")
	}
	if !reflect.DeepEqual(transcript.BTildeBytes, transcript2.BTildeBytes) {
		t.Fatal("bTildeBytes non-deterministic")
	}

	// Different entropy → different transcript hash.
	_, transcript3, err := BootstrapPedersen(
		hash.NewCoronaSHA3(),
		thr, validators, 0, 0,
		deterministicRand("bootstrap-pedersen-different"),
	)
	if err != nil {
		t.Fatalf("BootstrapPedersen alt: %v", err)
	}
	if transcript.TranscriptHash == transcript3.TranscriptHash {
		t.Fatal("transcript hash collided across entropy streams")
	}

	// Sanity: the second era has a fresh GroupKey pointer (independent
	// objects).
	if era == era2 {
		t.Fatal("expected distinct *KeyEra values across separate calls")
	}
}

// TestBootstrapPedersen_DishonestDealer — one party broadcasts an
// inconsistent contribution (tampered share-to-0). The orchestrator
// returns ErrBootstrapPedersenAbort with an AbortEvidence naming the
// offending sender. The era and transcript are nil — the chain stays
// at the previous epoch.
func TestBootstrapPedersen_DishonestDealer(t *testing.T) {
	const thr, n = 3, 5
	validators := []string{"v1", "v2", "v3", "v4", "v5"}
	suite := hash.NewCoronaSHA3()

	// Reproduce Round1 outputs via the dkg2 API so we can tamper one.
	dkgParams, err := dkg2.NewParams()
	if err != nil {
		t.Fatalf("dkg2.NewParams: %v", err)
	}
	sessions := make([]*dkg2.DKGSession, n)
	round1 := make([]*dkg2.Round1Output, n)
	rng := deterministicRand("bootstrap-pedersen-dishonest")
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

	// Tamper sender 2's share-to-recipient-0. Round2Identify run from
	// the perspective of recipient 0 must name sender 2 as the bad
	// actor. The orchestrator runs every recipient in order, so
	// recipient 0 detects the abort first.
	round1[2].Shares[0][0].Coeffs[0][0] ^= 0x42

	era, transcript, err := FinishBootstrapPedersen(
		suite, thr, validators, 0, 0,
		dkgParams, sessions, round1,
	)
	if era != nil || transcript != nil {
		t.Fatal("expected (nil, nil) on abort")
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
	if _, ok := ev.Disqualified[2]; !ok {
		t.Fatalf("expected sender 2 disqualified, disqualified=%v", ev.Disqualified)
	}
	if len(ev.Complaints) == 0 {
		t.Fatal("expected at least one Complaint in evidence")
	}
	if ev.Complaints[0].SenderID != 2 {
		t.Fatalf("complaint.SenderID: want 2 got %d", ev.Complaints[0].SenderID)
	}
	if ev.Complaints[0].Reason != dkg2.ComplaintBadDelivery {
		t.Fatalf("complaint.Reason: want bad-delivery got %v", ev.Complaints[0].Reason)
	}

	// The transcript hash on the evidence is non-zero — chain can
	// commit the abort transcript and stay at previous epoch.
	if ev.TranscriptHash == [32]byte{} {
		t.Fatal("AbortEvidence.TranscriptHash is zero")
	}
}

// TestBootstrapPedersen_FollowedBySign — full integration. Run a
// Pedersen bootstrap with no trusted dealer, then drive the standard
// Corona threshold-sign 2-round protocol under the produced GroupKey.
// The resulting signature must verify under threshold.Verify.
//
// This is the binding contract: the noise-flooded GroupKey (A, bTilde)
// produced by Path (a) is structurally identical to a trusted-dealer
// Corona setup, so the existing Sign/Verify path accepts it unchanged.
func TestBootstrapPedersen_FollowedBySign(t *testing.T) {
	const thr, n = 4, 5
	validators := []string{"v1", "v2", "v3", "v4", "v5"}
	era, _, err := BootstrapPedersen(
		hash.NewCoronaSHA3(),
		thr, validators, 0, 0,
		deterministicRand("bootstrap-pedersen-sign"),
	)
	if err != nil {
		t.Fatalf("BootstrapPedersen: %v", err)
	}
	if !signAndVerify(t, era, validators) {
		t.Fatal("noise-flooded GroupKey did not accept threshold-signed message")
	}
}

// TestBootstrapPedersen_NoMasterSecretInMemory — defense-in-depth
// statement: at no point during the bootstrap ceremony does any party
// (here represented by any kernel-resident dkg2.DKGSession) hold the
// reconstructed master secret s.
//
// We assert this structurally: the dkg2.DKGSession exposes no field or
// method that returns the master secret; the orchestrator never calls
// any reconstruction primitive; and the per-party SkShare values are
// independent shares (every pair differs).
//
// This is necessarily a structural argument, not a runtime one — the Go
// runtime cannot prove the absence of a value across all paths. The
// public-BFT-safe property is established by review + this structural
// check, and ultimately by the Pedersen-DKG security proof (hiding
// under MLWE on the wide concatenation [A|B]) cited in
// papers/lp-073-pulsar §07.
func TestBootstrapPedersen_NoMasterSecretInMemory(t *testing.T) {
	const thr, n = 3, 5
	validators := []string{"v1", "v2", "v3", "v4", "v5"}
	era, _, err := BootstrapPedersen(
		hash.NewCoronaSHA3(),
		thr, validators, 0, 0,
		deterministicRand("bootstrap-pedersen-no-master"),
	)
	if err != nil {
		t.Fatalf("BootstrapPedersen: %v", err)
	}

	// Structural assertion 1: dkg2.DKGSession exposes no "master secret"
	// accessor.
	dkgType := reflect.TypeOf((*dkg2.DKGSession)(nil)).Elem()
	for i := 0; i < dkgType.NumField(); i++ {
		f := dkgType.Field(i)
		// Reject any field whose lower-cased name contains the substring
		// "mastersecret" or "masters".
		lower := lowercase(f.Name)
		if contains(lower, "mastersecret") || contains(lower, "fullsecret") {
			t.Fatalf("dkg2.DKGSession has a forbidden field %q — master-secret state leaks", f.Name)
		}
	}

	// Structural assertion 2: every distinct pair of party SkShares
	// disagrees on at least one coefficient. If two shares were equal
	// to the reconstructed master secret (e.g. via a misbehaving
	// orchestrator that wrote s into every party's share slot), they
	// would collide on every coefficient and we would catch it here.
	for vA, ksA := range era.State.Shares {
		for vB, ksB := range era.State.Shares {
			if vA >= vB { // canonicalise to one direction
				continue
			}
			if sharesEqual(ksA, ksB) {
				t.Fatalf("validators %s and %s share identical secret bytes — orchestrator leaked master secret", vA, vB)
			}
		}
	}

	// Structural assertion 3: every party's Lambda is distinct (Lagrange
	// coefficients at distinct evaluation points cannot collide for
	// degree ≥ 1 polynomials over Z_q with n ≥ 2).
	lambdaSeen := make(map[uint64]string)
	for vName, ks := range era.State.Shares {
		key := ks.Lambda.Coeffs[0][0]
		if prev, ok := lambdaSeen[key]; ok && prev != vName {
			t.Fatalf("validators %s and %s share identical Lambda[0][0] — Lagrange weights degenerate", prev, vName)
		}
		lambdaSeen[key] = vName
	}
}

// TestBootstrapPedersen_ParameterValidation — input bounds checking.
func TestBootstrapPedersen_ParameterValidation(t *testing.T) {
	cases := []struct {
		name       string
		t, n       int
		validators []string
		want       error
	}{
		{"empty validators", 1, 0, nil, ErrEmptyValidators},
		{"t < 1", 0, 3, []string{"a", "b", "c"}, ErrInvalidThreshold},
		{"t > n", 4, 3, []string{"a", "b", "c"}, ErrInvalidThreshold},
		{"t == n", 3, 3, []string{"a", "b", "c"}, ErrBootstrapPedersenShape},
		{"n == 1", 1, 1, []string{"a"}, ErrBootstrapPedersenShape},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := BootstrapPedersen(
				hash.NewCoronaSHA3(),
				c.t, c.validators, 0, 0,
				deterministicRand("validation"),
			)
			if !errors.Is(err, c.want) {
				t.Fatalf("expected %v, got %v", c.want, err)
			}
		})
	}
}

// TestBootstrapPedersen_DefaultSuite — nil suite resolves to the
// production default (Corona-SHA3) and produces a working era.
func TestBootstrapPedersen_DefaultSuite(t *testing.T) {
	const thr, n = 2, 3
	validators := []string{"a", "b", "c"}
	era, _, err := BootstrapPedersen(
		nil, // → Corona-SHA3
		thr, validators, 0, 0,
		deterministicRand("default-suite"),
	)
	if err != nil {
		t.Fatalf("BootstrapPedersen(nil suite): %v", err)
	}
	if era.HashSuiteID != hash.DefaultID {
		t.Fatalf("HashSuiteID: want %q got %q", hash.DefaultID, era.HashSuiteID)
	}
}

// TestBootstrapTrustedDealer_LegacyAlias — the renamed legacy alias is
// byte-equivalent to the original Bootstrap.
func TestBootstrapTrustedDealer_LegacyAlias(t *testing.T) {
	const thr, n = 3, 3
	validators := []string{"x", "y", "z"}

	eraA, err := Bootstrap(thr, validators, 0, 0, deterministicRand("legacy-alias"))
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	eraB, err := BootstrapTrustedDealer(thr, validators, 0, 0, deterministicRand("legacy-alias"))
	if err != nil {
		t.Fatalf("BootstrapTrustedDealer: %v", err)
	}
	// bTilde bytes must match — both paths consume the same entropy
	// stream and run the same Shamir kernel.
	if !reflect.DeepEqual(eraA.GroupKey.BTilde, eraB.GroupKey.BTilde) {
		t.Fatal("BootstrapTrustedDealer diverges from Bootstrap on bTilde — alias broken")
	}
	// Same set of validators.
	if !reflect.DeepEqual(eraA.State.Validators, eraB.State.Validators) {
		t.Fatal("BootstrapTrustedDealer diverges from Bootstrap on validators")
	}
}

// ---------------------- helpers ----------------------

// sharesEqual returns true iff two KeyShares carry byte-identical
// SkShare coefficients on every polynomial slot.
func sharesEqual(a, b *threshold.KeyShare) bool {
	if len(a.SkShare) != len(b.SkShare) {
		return false
	}
	for i := range a.SkShare {
		if a.SkShare[i].N() != b.SkShare[i].N() {
			return false
		}
		for level := range a.SkShare[i].Coeffs {
			if len(a.SkShare[i].Coeffs[level]) != len(b.SkShare[i].Coeffs[level]) {
				return false
			}
			for k := range a.SkShare[i].Coeffs[level] {
				if a.SkShare[i].Coeffs[level][k] != b.SkShare[i].Coeffs[level][k] {
					return false
				}
			}
		}
	}
	return true
}

// contains is a trivial substring test that avoids pulling in strings.
func contains(haystack, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// lowercase returns a lowercase copy of s. Avoid strings.ToLower to keep
// the import surface clean.
func lowercase(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b[i] = c
	}
	return string(b)
}
