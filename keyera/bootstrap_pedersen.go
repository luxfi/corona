// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keyera

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/luxfi/corona/hash"
	"github.com/luxfi/corona/sign"
	"github.com/luxfi/corona/threshold"
	"github.com/luxfi/corona/utils"

	dkgblame "github.com/luxfi/dkg/blame"
	dkgchannel "github.com/luxfi/dkg/channel"
	dkgring "github.com/luxfi/dkg/ring"
	dkgvss "github.com/luxfi/dkg/vss"

	lring "github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/sampling"
	"github.com/luxfi/lattice/v7/utils/structs"

	"github.com/zeebo/blake3"
)

// bootstrap_pedersen.go — dealerless key-era bootstrap.
//
// The no-reconstruct Pedersen-VSS share-dealing (commit & deal, equivocation
// gate, Pedersen verification, identifiable abort) is provided by the shared
// github.com/luxfi/dkg library, parameterized by ring.Ringtail(). corona keeps
// ONLY its scheme-specific finalize: Path (a) noise flooding + Round_Xi, which
// turns the per-party secret shares s_j into the LWE-shaped Ringtail public key
// bTilde = Round_Xi(A·s + e″). The Pedersen aggregate T = A·s1+B·u that vss
// produces is NOT used as the group key (its B·u term is not a small LWE error);
// vss is used purely for the no-reconstruct share distribution + blame.
//
// Byte-stability (golden_bootstrap_kat_test.go): the per-party sampling seed is
// threaded into vss's Round1 so the χ draws — hence the Pedersen commits and the
// secret shares — are byte-identical to the prior dkg2 path; the commit digests
// are recomputed under the corona HashSuite over the same commit bytes. So the
// group key, shares, and transcript are PRESERVED, not re-baselined.

// BootstrapTranscript is the public, byte-stable record produced by a
// BootstrapPedersen run. Every honest validator that observes the same
// cohort messages computes identical transcript bytes; the chain commits
// to TranscriptHash to ratify the era.
//
// Fields are exported so the consensus layer can ship the transcript over
// the wire and re-derive each honest party's view from it. No secret
// material appears here.
//
//	Validators       — ordered validator IDs (matches KeyEra.State.Validators).
//	Threshold        — reconstruction threshold t (1 ≤ t ≤ n).
//	HashSuiteID      — pinned suite ID, e.g. "Corona-SHA3".
//	Round1Digests    — per-party Round 1.5 commit digest under the suite.
//	BetaSerialized   — per-party β_j ∈ R_q^M bytes (in NTT-Mont form), ordered
//	                   by party index. Σ_j β_j (NTT-Mont) is the noise-flooded
//	                   public key b in standard form before rounding.
//	BTildeBytes      — canonical wire bytes of the final bTilde (Round_Xi(b)).
//	TranscriptHash   — HashSuite digest binding all of the above.
//
// Slashing evidence (signed Complaint) MUST be carried alongside this
// transcript when the run completes with non-empty disqualifications;
// BootstrapPedersen returns a stand-alone error in that case.
type BootstrapTranscript struct {
	Validators     []string
	Threshold      int
	HashSuiteID    string
	Round1Digests  [][32]byte
	BetaSerialized [][]byte
	BTildeBytes    []byte
	TranscriptHash [32]byte
}

// AbortEvidence captures the signed Complaint set that aborted a
// BootstrapPedersen run. The chain stays at the previous era and the
// returned error wraps ErrBootstrapPedersenAbort.
//
// Complaints are the shared library's scheme-agnostic blame records (a bad
// share is named by the accused validator's NodeID, re-checkable by any third
// party via vss.RecheckBadDelivery). Disqualified maps the committee index of
// each named dealer.
type AbortEvidence struct {
	TranscriptHash [32]byte
	Complaints     []*dkgblame.Complaint
	Disqualified   map[int]struct{}
}

// Errors specific to the Pedersen-DKG bootstrap path.
var (
	// ErrBootstrapPedersenAbort is returned when the run identifies one or
	// more misbehaving senders. The caller receives an AbortEvidence.
	ErrBootstrapPedersenAbort = errors.New("keyera: bootstrap-pedersen aborted with identifiable evidence")

	// ErrBootstrapPedersenShape is returned when input parameters violate
	// the (1 ≤ t ≤ n) and (n ≥ 2) constraints required by the DKG.
	ErrBootstrapPedersenShape = errors.New("keyera: bootstrap-pedersen parameter shape")
)

// noiseFloodTag is the domain-separation prefix for the Path (a)
// noise-flooding sub-protocol described in
// papers/lp-073-pulsar/sections/07-pedersen-dkg.tex §Mapping. It binds
// every Gaussian seed e_j' to the canonical bootstrap transcript so two
// concurrent eras cannot share noise.
const noiseFloodTag = "CORONA-BOOTSTRAP-PEDERSEN-NOISEFLOOD-v1"

// transcriptTag is the domain-separation prefix for the final
// BootstrapTranscript hash. The active HashSuite ID is bound into the
// transcript so two suites can never collide on a single era.
const transcriptTag = "CORONA-BOOTSTRAP-PEDERSEN-TRANSCRIPT-v1"

// tagCommitDigest is the customization tag bound into the Round 1.5 commit
// digest under the active HashSuite. The suite ID is bound into the digest
// input as well so two suites can never produce a colliding digest for the
// same commit vector. The string is the historical corona/dkg2 tag, kept
// verbatim so the digest — hence the noise seed and the transcript hash —
// is byte-identical across the move to luxfi/dkg.
const tagCommitDigest = "CORONA-DKG2-COMMIT-DIGEST-v1"

// identityDomainTag derives the per-party long-term DKG channel identities
// deterministically. The identities authenticate the sealed share envelopes;
// they do NOT influence the public commits, the secret shares, or the group
// key (those are functions of the per-party sampling seed only), so a fixed
// derivation keeps the whole in-process run replayable without perturbing any
// byte-stable output.
const identityDomainTag = "CORONA-BOOTSTRAP-PEDERSEN-IDENTITY-v1"

// kemStreamTag derives the per-party KEM-encapsulation randomness stream that
// vss.Round1 consumes after the 32-byte sampling seed. Like the identities,
// this affects only the (immediately-opened, then-discarded) envelope
// ciphertext, never any byte-stable output.
const kemStreamTag = "CORONA-BOOTSTRAP-PEDERSEN-KEMSTREAM-v1"

// pedersenSession bundles the in-process vss machinery for one bootstrap: the
// Ringtail profile, the n party sessions, their deterministic identities, the
// committee NodeIDs, and the era/committee context. corona drives every party
// itself (in-process reference path); production wraps each party over an
// authenticated network at the consensus layer.
type pedersenSession struct {
	profile *dkgring.Profile
	parties []*dkgvss.Party
	ids     []*dkgchannel.IdentityKey
	nodes   []dkgchannel.NodeID
	context [32]byte
	cr      *lring.Ring // corona ring (== profile.Ring.Base()) for Path (a)
	crXi    *lring.Ring // post-rounding ring for Round_Xi
}

// PedersenContributions is the raw share-dealing output of all parties' Round 1
// plus, per recipient, the opened (share, blind, commits) it verifies in
// Round 3. It feeds FinishBootstrapPedersen. Tests use it to simulate an
// identifiable-abort: they tamper one opened share and call
// FinishBootstrapPedersen to drive the blame path.
//
// In production the per-party Round-1 broadcasts + sealed envelopes arrive over
// the network and the consensus layer assembles them; this kernel exists for
// tests + the single-process integration suite.
type PedersenContributions struct {
	session *pedersenSession
	// commits[i] is dealer i's broadcast Pedersen commit vector (plain-NTT).
	commits [][]dkgring.Vector
	// digests[i] is the corona-HashSuite commit digest of dealer i's commits.
	digests [][32]byte
	// inputs[j][i] is recipient j's opened contribution from dealer i.
	inputs []map[int]*dkgvss.DealerInput
}

// BootstrapPedersen opens a new key era WITHOUT a trusted dealer.
//
// The construction follows Path (a) of papers/lp-073-pulsar §07:
//
//  1. Each party runs the shared Pedersen-VSS Round 1 → broadcasts Pedersen
//     commits, KEM-seals (share_{i→j}, blind_{i→j}) privately to recipient j.
//  2. Each party verifies all incoming Pedersen pairs (constant-time
//     comparison; identifiable abort on mismatch).
//  3. Each party aggregates its share s_j of the master secret s. NO PARTY
//     ever holds s in memory (no-reconstruct: vss never sums the contributions).
//  4. Each party samples a fresh Gaussian e_j' ~ D(σ″) locally with
//     σ″ = κ · σ_E · √n (the slack reservation of LP-073 §5) and
//     broadcasts β_j = A · NTT(λ_j · s_j) + e_j'. The published β_j is
//     LWE-protected by e_j' so no party learns more than its own share.
//  5. All parties aggregate b = Σ_j β_j = A · s + e″ in NTT-Mont; the
//     Corona-Sign-shaped public key is bTilde = Round_Xi(b).
//
// On success returns (era, transcript, nil). On identifiable abort returns
// (nil, nil, ErrBootstrapPedersenAbort) with the AbortEvidence wrapped into
// the error (extract via ExtractAbortEvidence).
//
// In production each party drives its own vss session over an authenticated
// network. This in-process kernel drives every party itself; it exists to (a)
// be the trusted-collaborator path for the single-process integration tests
// and (b) provide a reference against which the distributed protocol can be
// byte-equality checked.
//
// Pass nil for the production suite default (Corona-SHA3).
func BootstrapPedersen(suite hash.HashSuite, t int, validators []string, groupID CoronaGroupID, eraID CoronaKeyEraID, entropy io.Reader) (*KeyEra, *BootstrapTranscript, error) {
	if len(validators) == 0 {
		return nil, nil, ErrEmptyValidators
	}
	n := len(validators)
	if t < 1 || t > n {
		return nil, nil, fmt.Errorf("%w: t=%d n=%d", ErrInvalidThreshold, t, n)
	}
	// The Pedersen DKG requires n ≥ 2 and 1 ≤ t < n (strictly less than for
	// honest-abort detection). For t == n callers must use the trusted-dealer
	// path because the DKG cannot guard a corruption-free quorum below 1.
	if n < 2 {
		return nil, nil, fmt.Errorf("%w: n=%d (dkg requires n >= 2)", ErrBootstrapPedersenShape, n)
	}
	if t >= n {
		return nil, nil, fmt.Errorf("%w: t=%d n=%d (dkg requires t < n)", ErrBootstrapPedersenShape, t, n)
	}
	if entropy == nil {
		entropy = rand.Reader
	}
	suite = hash.Resolve(suite)
	suiteID := suite.ID()

	// Draw the per-party sampling seeds from the ceremony entropy, canonically
	// sequenced (matches the prior dkg2 path's entropy consumption exactly, so
	// the χ draws — hence commits, shares, and bTilde — are byte-stable).
	round1Seeds := make([][]byte, n)
	for i := 0; i < n; i++ {
		seed := make([]byte, sign.KeySize)
		if _, err := io.ReadFull(entropy, seed); err != nil {
			return nil, nil, fmt.Errorf("keyera: bootstrap-pedersen entropy[%d]: %w", i, err)
		}
		round1Seeds[i] = seed
	}

	contribs, err := dealPedersen(suite, t, n, round1Seeds)
	if err != nil {
		return nil, nil, err
	}
	return finishPedersenContribs(suite, suiteID, t, n, validators, groupID, eraID, contribs)
}

// newPedersenSession builds the in-process committee: the Ringtail profile, n
// deterministic channel identities, NodeIDs, the identity directory, the
// corona rings, and one vss.Party per committee position.
func newPedersenSession(t, n int) (*pedersenSession, error) {
	profile, err := dkgring.Ringtail()
	if err != nil {
		return nil, fmt.Errorf("keyera: bootstrap-pedersen ring.Ringtail: %w", err)
	}
	crXi, _ := lring.NewRing(1<<sign.LogN, []uint64{sign.QXi}) // non-prime modulus; error deliberately ignored (RoundVector container only)

	ids := make([]*dkgchannel.IdentityKey, n)
	nodes := make([]dkgchannel.NodeID, n)
	entries := make(map[dkgchannel.NodeID]*dkgchannel.IdentityPublicKey, n)
	for i := 0; i < n; i++ {
		id, err := dkgchannel.GenerateIdentity(derivedStream(identityDomainTag, uint32(i)))
		if err != nil {
			return nil, fmt.Errorf("keyera: bootstrap-pedersen identity[%d]: %w", i, err)
		}
		ids[i] = id
		nodes[i] = pedersenNodeID(i)
		entries[nodes[i]] = id.PublicKey()
	}
	dir, err := dkgchannel.NewIdentityDirectory(entries)
	if err != nil {
		return nil, fmt.Errorf("keyera: bootstrap-pedersen directory: %w", err)
	}

	// The era/committee context binds every envelope to this ceremony. It is
	// public and deterministic from (t, n); the consensus layer overrides it
	// with a chain transcript root in the distributed deployment.
	var context [32]byte
	ctx := blake3.New()
	_, _ = ctx.Write([]byte("CORONA-BOOTSTRAP-PEDERSEN-CONTEXT-v1"))
	_, _ = ctx.Write(u32be(uint32(t)))
	_, _ = ctx.Write(u32be(uint32(n)))
	copy(context[:], ctx.Sum(nil))

	parties := make([]*dkgvss.Party, n)
	for i := 0; i < n; i++ {
		p, err := dkgvss.NewParty(profile, nodes[i], ids[i], i, n, t, nodes, dir, context)
		if err != nil {
			return nil, fmt.Errorf("keyera: bootstrap-pedersen NewParty[%d]: %w", i, err)
		}
		parties[i] = p
	}

	return &pedersenSession{
		profile: profile,
		parties: parties,
		ids:     ids,
		nodes:   nodes,
		context: context,
		cr:      profile.Ring.Base(),
		crXi:    crXi,
	}, nil
}

// dealPedersen drives the shared Pedersen-VSS Round 1 for every party (with the
// per-party sampling seed threaded so the χ draws are byte-identical to the
// prior dkg2 path), computes the corona commit digests, then opens every sealed
// envelope so each recipient holds its (share, blind, commits) from each dealer.
// The honest-path Pedersen verification + aggregation happens in
// finishPedersenContribs (so a test can tamper an opened share first).
func dealPedersen(suite hash.HashSuite, t, n int, round1Seeds [][]byte) (*PedersenContributions, error) {
	if len(round1Seeds) != n {
		return nil, fmt.Errorf("%w: seeds=%d n=%d", ErrBootstrapPedersenShape, len(round1Seeds), n)
	}
	sess, err := newPedersenSession(t, n)
	if err != nil {
		return nil, err
	}

	// Round 1: each party samples χ, builds Pedersen commits, seals shares.
	round1 := make([]*dkgvss.Round1Out, n)
	for i := 0; i < n; i++ {
		out, err := sess.parties[i].Round1(seededRound1Rng(round1Seeds[i], i))
		if err != nil {
			return nil, fmt.Errorf("keyera: bootstrap-pedersen Round1[%d]: %w", i, err)
		}
		round1[i] = out
	}

	// Commit digests under the corona HashSuite (Round 1.5 equivocation gate +
	// transcript binding). Computed over the lattigo wire bytes of each dealer's
	// commits — byte-identical to the prior dkg2 CommitDigest.
	commits := make([][]dkgring.Vector, n)
	digests := make([][32]byte, n)
	for i := 0; i < n; i++ {
		commits[i] = round1[i].Commits
		d, err := coronaCommitDigest(suite, round1[i].Commits)
		if err != nil {
			return nil, fmt.Errorf("keyera: bootstrap-pedersen CommitDigest[%d]: %w", i, err)
		}
		digests[i] = d
	}

	// Open every sealed envelope: recipient j recovers (share, blind) from each
	// dealer i. The opened values are byte-identical to the dealer's Horner
	// evaluation f_i(j+1) / g_i(j+1).
	inputs := make([]map[int]*dkgvss.DealerInput, n)
	for j := 0; j < n; j++ {
		row := make(map[int]*dkgvss.DealerInput, n)
		for i := 0; i < n; i++ {
			share, blind, err := sess.parties[j].OpenDealerShare(i, round1[i].Envelopes[j])
			if err != nil {
				return nil, fmt.Errorf("keyera: bootstrap-pedersen open[%d<-%d]: %w", j, i, err)
			}
			row[i] = &dkgvss.DealerInput{Commits: round1[i].Commits, Share: share, Blind: blind}
		}
		inputs[j] = row
	}

	return &PedersenContributions{
		session: sess,
		commits: commits,
		digests: digests,
		inputs:  inputs,
	}, nil
}

// finishPedersenContribs runs Round 3 (Pedersen verify + aggregate) for every
// recipient over the opened contributions, then the Path (a) noise flooding and
// KeyShare assembly. On the first dealer whose contribution fails verification
// it returns ErrBootstrapPedersenAbort with re-checkable blame evidence.
func finishPedersenContribs(suite hash.HashSuite, suiteID string, t, n int, validators []string, groupID CoronaGroupID, eraID CoronaKeyEraID, contribs *PedersenContributions) (*KeyEra, *BootstrapTranscript, error) {
	sess := contribs.session
	cr := sess.cr
	digests := contribs.digests

	// Round 3 — each recipient verifies every dealer's (share, blind) against
	// the commits and aggregates its own secret share s_j. On any identifiable
	// abort we mint a signed complaint and return.
	sShares := make([]structs.Vector[lring.Poly], n)
	for j := 0; j < n; j++ {
		res, fault, err := sess.parties[j].Round3(contribs.inputs[j])
		if err != nil {
			if fault == nil {
				return nil, nil, fmt.Errorf("keyera: bootstrap-pedersen Round3[%d]: %w", j, err)
			}
			abortEv, abortErr := buildAbortEvidence(sess, suite, suiteID, digests, n, t, validators, fault)
			if abortErr != nil {
				return nil, nil, fmt.Errorf("keyera: bootstrap-pedersen Round3[%d] + abort-evidence: %v / %w", j, abortErr, err)
			}
			return nil, nil, fmt.Errorf("%w: %w", ErrBootstrapPedersenAbort, abortEvidenceWrap(abortEv, err))
		}
		sShares[j] = res.Share
	}

	// Path (a) noise flooding. Compute Lagrange weights at X=0 for the full
	// committee T = {0, ..., n-1}; each party scales its share by λ_j so the
	// aggregate equals s. Each party then adds a fresh Gaussian e_j' under
	// σ″ = κ · σ_E · √n. The deterministic noise seed is derived from the
	// active HashSuite over the canonical transcript prefix so a KAT replay can
	// reproduce the bootstrap byte-for-byte from a single entropy source.
	A := sess.profile.A
	lagrange := computeFullCommitteeLagrange(cr, n)

	bSum := utils.InitializeVector(cr, sign.M)
	betaSerialized := make([][]byte, n)
	noiseSigma, noiseBound := pathANoiseParameters(n)

	noiseSeedTranscript := suite.TranscriptHash(
		[]byte(noiseFloodTag),
		[]byte(suiteID),
		framedJoin(digests),
		framedJoinValidators(validators),
		framedJoinUint32([]uint32{uint32(t), uint32(n)}),
	)

	for j := 0; j < n; j++ {
		// λ_j in NTT-Mont form for the multiplication.
		lambda := cr.NewPoly()
		lambda.Copy(lagrange[j])
		cr.NTT(lambda, lambda)
		cr.MForm(lambda, lambda)

		// NTT-Mont share s_j scaled by λ_j: λ_j · NTT-Mont(s_j).
		// sShares[j] is in standard coefficient form; convert to NTT-Mont.
		sNTT := make(structs.Vector[lring.Poly], sign.N)
		for vi := 0; vi < sign.N; vi++ {
			sNTT[vi] = *sShares[j][vi].CopyNew()
			cr.NTT(sNTT[vi], sNTT[vi])
			cr.MForm(sNTT[vi], sNTT[vi])
		}

		// (λ_j · s_j) coordinate-wise.
		scaled := make(structs.Vector[lring.Poly], sign.N)
		for vi := 0; vi < sign.N; vi++ {
			scaled[vi] = cr.NewPoly()
			cr.MulCoeffsMontgomery(sNTT[vi], lambda, scaled[vi])
		}

		// β_j = A · (λ_j · s_j) + e_j' where e_j' ~ D(σ″).
		Aprod := utils.InitializeVector(cr, sign.M)
		utils.MatrixVectorMul(cr, A, scaled, Aprod)

		ePrime := samplePathANoise(cr, suite, noiseSeedTranscript, j, noiseSigma, noiseBound)
		// ePrime is in NTT-Mont; β_j = Aprod + ePrime.
		beta := utils.InitializeVector(cr, sign.M)
		utils.VectorAdd(cr, Aprod, ePrime, beta)

		// Serialize β_j for the transcript.
		buf, serr := serializeVector(beta)
		if serr != nil {
			return nil, nil, fmt.Errorf("keyera: bootstrap-pedersen serialize beta[%d]: %w", j, serr)
		}
		betaSerialized[j] = buf

		// Accumulate.
		utils.VectorAdd(cr, bSum, beta, bSum)
	}

	// b = Σ_j β_j = A·s + e″ in NTT-Mont. Convert to standard form, then round
	// to bTilde under the QXi ring.
	utils.ConvertVectorFromNTT(cr, bSum)
	bTilde := utils.RoundVector(cr, sess.crXi, bSum, sign.Xi)

	// Build Corona threshold.GroupKey. The matrix A is the Ringtail A
	// (nothing-up-my-sleeve, byte-identical to the prior dkg2 A), so the era is
	// reproducible from the transcript alone.
	thParams, err := threshold.NewParams()
	if err != nil {
		return nil, nil, fmt.Errorf("keyera: bootstrap-pedersen threshold params: %w", err)
	}
	gk := &threshold.GroupKey{
		A:      A,
		BTilde: bTilde,
		Params: thParams,
	}

	// Pairwise seeds and MAC keys. In a distributed deployment these come from
	// authenticated pairwise KEX (reshare/pairwise.go); the kernel derives them
	// deterministically from the transcript so KATs can replay. The bytes are
	// independent of any secret share material — they form a public symmetric
	// mask the cohort agrees on (protection comes from each party's SkShare).
	seedTranscript := suite.TranscriptHash(
		[]byte("CORONA-BOOTSTRAP-PEDERSEN-PAIRWISE-v1"),
		noiseSeedTranscript[:],
		bTildeBytes(bTilde),
	)
	seeds, macKeysByParty := derivePairwisePedersen(n, seedTranscript)

	// Assemble per-party KeyShares.
	state := &EpochShareState{
		KeyEraID:     uint64(eraID),
		HashSuiteID:  suiteID,
		Generation:   0,
		RollbackFrom: 0,
		Epoch:        0,
		Validators:   append([]string(nil), validators...),
		Threshold:    t,
		Shares:       make(map[string]*threshold.KeyShare, n),
	}
	for j, v := range validators {
		// sShares[j] is in standard form; convert to NTT-Mont for the
		// signing-time multiplication path (matches the trusted-dealer
		// convention).
		skNTT := make(structs.Vector[lring.Poly], sign.N)
		for vi := 0; vi < sign.N; vi++ {
			skNTT[vi] = *sShares[j][vi].CopyNew()
		}
		utils.ConvertVectorToNTT(thParams.R, skNTT)

		lambda := thParams.R.NewPoly()
		lambda.Copy(lagrange[j])
		thParams.R.NTT(lambda, lambda)
		thParams.R.MForm(lambda, lambda)

		state.Shares[v] = &threshold.KeyShare{
			Index:    j,
			SkShare:  skNTT,
			Seeds:    seeds,
			MACKeys:  macKeysByParty[j],
			Lambda:   lambda,
			GroupKey: gk,
		}
	}

	transcript := &BootstrapTranscript{
		Validators:     append([]string(nil), validators...),
		Threshold:      t,
		HashSuiteID:    suiteID,
		Round1Digests:  digests,
		BetaSerialized: betaSerialized,
		BTildeBytes:    bTildeBytes(bTilde),
	}
	transcript.TranscriptHash = suite.TranscriptHash(
		[]byte(transcriptTag),
		[]byte(suiteID),
		framedJoinValidators(validators),
		framedJoinUint32([]uint32{uint32(t), uint32(n)}),
		framedJoin(digests),
		framedJoinBytes(betaSerialized),
		transcript.BTildeBytes,
	)

	return &KeyEra{
		EraID:        eraID,
		GroupID:      groupID,
		GroupKey:     gk,
		GenesisEpoch: 0,
		HashSuiteID:  suiteID,
		State:        state,
	}, transcript, nil
}

// DealPedersen runs the share-dealing half of BootstrapPedersen (Round 1 +
// envelope opening) over the supplied per-party sampling seeds and returns the
// opened contributions. Tests use this to tamper one opened share before
// calling FinishBootstrapPedersen, exercising the identifiable-abort path.
//
// seeds must have exactly n = len(validators) entries of sign.KeySize bytes.
func DealPedersen(suite hash.HashSuite, t int, validators []string, seeds [][]byte) (*PedersenContributions, error) {
	if len(validators) == 0 {
		return nil, ErrEmptyValidators
	}
	n := len(validators)
	if t < 1 || t > n {
		return nil, fmt.Errorf("%w: t=%d n=%d", ErrInvalidThreshold, t, n)
	}
	if n < 2 || t >= n {
		return nil, fmt.Errorf("%w: t=%d n=%d", ErrBootstrapPedersenShape, t, n)
	}
	if len(seeds) != n {
		return nil, fmt.Errorf("%w: seeds=%d n=%d", ErrBootstrapPedersenShape, len(seeds), n)
	}
	return dealPedersen(hash.Resolve(suite), t, n, seeds)
}

// FinishBootstrapPedersen takes a fully assembled set of opened contributions
// (produced by DealPedersen) and drives the remainder of the protocol: Round 3
// verification, Path (a) noise flooding, and KeyShare assembly.
//
// In production the contributions arrive over the network; in tests the caller
// may tamper one opened share to exercise the identifiable-abort path.
//
// suite=nil resolves to the production default (Corona-SHA3).
func FinishBootstrapPedersen(suite hash.HashSuite, t int, validators []string, groupID CoronaGroupID, eraID CoronaKeyEraID, contribs *PedersenContributions) (*KeyEra, *BootstrapTranscript, error) {
	if len(validators) == 0 {
		return nil, nil, ErrEmptyValidators
	}
	n := len(validators)
	if t < 1 || t > n {
		return nil, nil, fmt.Errorf("%w: t=%d n=%d", ErrInvalidThreshold, t, n)
	}
	if n < 2 || t >= n {
		return nil, nil, fmt.Errorf("%w: t=%d n=%d", ErrBootstrapPedersenShape, t, n)
	}
	if contribs == nil || contribs.session == nil || len(contribs.inputs) != n {
		return nil, nil, fmt.Errorf("%w: malformed contributions", ErrBootstrapPedersenShape)
	}
	suite = hash.Resolve(suite)
	return finishPedersenContribs(suite, suite.ID(), t, n, validators, groupID, eraID, contribs)
}

// BootstrapTrustedDealer is the legacy single-trusted-party bootstrap
// retained for HSM/TEE ceremony scenarios where a non-distributed
// trust root is acceptable by policy (e.g. a publicly observable
// foundation MPC ceremony at chain launch). The dealer's host
// platform is in the trust boundary for the duration of the call.
//
// TRUST MODEL — TRUSTED DEALER (explicit opt-in).
// This function instantiates the master secret s on a single party
// (the dealer) for the duration of one stack frame. The dealer
// constructs Shamir shares of s, hands them to the validator set,
// and zeroes the in-memory copy of s before returning. The chain
// only holds the public GroupKey and the distributed shares
// thereafter. The dealer is in the TCB for the duration of the call.
//
// PREFER Bootstrap (the unqualified entrypoint) for any deployment
// where no single party is trusted to discard the master secret;
// Bootstrap routes through Pedersen-DKG (no dealer) by default.
//
// See DEPLOYMENT-RUNBOOK.md §Bootstrap-Trust for the trust-model
// decision matrix (which entry to use when).
func BootstrapTrustedDealer(t int, validators []string, groupID CoronaGroupID, eraID CoronaKeyEraID, entropy io.Reader) (*KeyEra, error) {
	return bootstrapTrustedDealerImpl(hash.Default(), t, validators, groupID, eraID, entropy)
}

// BootstrapTrustedDealerWithSuite is the suite-explicit form of
// BootstrapTrustedDealer. See its docstring for the trust-model
// disclosure.
func BootstrapTrustedDealerWithSuite(suite hash.HashSuite, t int, validators []string, groupID CoronaGroupID, eraID CoronaKeyEraID, entropy io.Reader) (*KeyEra, error) {
	return bootstrapTrustedDealerImpl(suite, t, validators, groupID, eraID, entropy)
}

// pathANoiseParameters returns the (σ, bound) pair for the Path (a)
// noise-flooding sub-protocol over a committee of n parties. The slack
// reservation σ″ = κ · σ_E · √n is the LP-073 §5 bound: it is large
// enough that the published β_j = A · (λ_j · s_j) + e_j' leaks no more
// information about s_j than a fresh LWE sample (the standard MLWE
// noise-flooding argument under DDH/MLWE).
//
// We bound the rejection-sampler tail at 2σ to match the discrete
// Gaussian convention used throughout corona/sign/.
func pathANoiseParameters(n int) (sigma, bound float64) {
	sigma = float64(sign.Kappa) * sign.SigmaE * math.Sqrt(float64(n))
	bound = sigma * 2
	return
}

// samplePathANoise draws one party's β_j noise contribution e_j' ~ D(σ).
//
// The Gaussian PRNG is seeded by HashSuite(noise-tag || party-index) so
// every honest party that re-derives the bootstrap transcript can verify
// the broadcast β_j byte-for-byte. In the production distributed protocol
// the seed comes from each party's own private RNG; here we derive
// deterministically for KAT-replay.
func samplePathANoise(r *lring.Ring, suite hash.HashSuite, transcript [32]byte, partyID int, sigma, bound float64) structs.Vector[lring.Poly] {
	var partyBuf [4]byte
	binary.BigEndian.PutUint32(partyBuf[:], uint32(partyID))
	seed := suite.TranscriptHash(
		transcript[:],
		[]byte("party"),
		partyBuf[:],
	)
	prng, _ := sampling.NewKeyedPRNG(seed[:])
	gauss := lring.NewGaussianSampler(prng, r,
		lring.DiscreteGaussian{Sigma: sigma, Bound: bound}, false)
	return utils.SamplePolyVector(r, sign.M, gauss, true, true)
}

// derivePairwisePedersen builds the per-pair PRF seeds and MAC keys for
// a committee of size n. The bytes are derived deterministically from a
// transcript-bound seed and contain no secret material (they form a
// public symmetric mask that the cohort agrees on; the protection comes
// from each party's own SkShare, not from the seeds).
//
// Layout matches derivePairwiseMaterial (used by trusted-dealer
// Bootstrap): seeds[i][j] for every (i, j); macKeys[i][j] symmetric for
// i ≠ j.
func derivePairwisePedersen(n int, transcriptSeed [32]byte) (map[int][][]byte, []map[int][]byte) {
	prng, _ := sampling.NewKeyedPRNG(transcriptSeed[:])
	seeds := make(map[int][][]byte, n)
	macKeys := make([]map[int][]byte, n)
	for i := 0; i < n; i++ {
		seeds[i] = make([][]byte, n)
		macKeys[i] = make(map[int][]byte, n-1)
	}
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			buf := make([]byte, sign.KeySize)
			prng.Read(buf)
			seeds[i][j] = buf
		}
	}
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			buf := make([]byte, sign.KeySize)
			prng.Read(buf)
			macKeys[i][j] = buf
			macKeys[j][i] = buf
		}
	}
	return seeds, macKeys
}

// coronaCommitDigest computes the Round 1.5 commit digest of a dealer's commit
// vector under the corona HashSuite. The digest is taken over the lattigo wire
// bytes of the commits, byte-identical to the prior dkg2 Round1Output.CommitDigest
// (same tag, same suite-ID binding, same serialization), so the noise seed and
// transcript hash are preserved across the move to luxfi/dkg.
func coronaCommitDigest(suite hash.HashSuite, commits []dkgring.Vector) ([32]byte, error) {
	var buf bytes.Buffer
	for _, v := range commits {
		if _, err := v.WriteTo(&buf); err != nil {
			return [32]byte{}, err
		}
	}
	return suite.TranscriptHash([]byte(tagCommitDigest), []byte(suite.ID()), buf.Bytes()), nil
}

// buildAbortEvidence packages a recipient's Round-3 VerifyFault into a signed
// blame complaint naming the offending dealer by NodeID, plus the disqualified
// committee index. The accuser is the recipient that observed the fault; it
// signs with its deterministic in-process identity. Any third party re-checks
// the accusation with vss.RecheckBadDelivery — no trust in the accuser.
func buildAbortEvidence(sess *pedersenSession, suite hash.HashSuite, suiteID string, digests [][32]byte, n, t int, validators []string, fault *dkgvss.VerifyFault) (*AbortEvidence, error) {
	transcriptHash := suite.TranscriptHash(
		[]byte(transcriptTag),
		[]byte(suiteID),
		framedJoinValidators(validators),
		framedJoinUint32([]uint32{uint32(t), uint32(n)}),
		framedJoin(digests),
	)
	accused := sess.nodes[fault.DealerIndex]
	accuser := sess.nodes[fault.RecipientIndex]
	c, err := dkgvss.NewBadDeliveryComplaint(
		sess.profile, fault, transcriptHash, accused, accuser, sess.ids[fault.RecipientIndex],
	)
	if err != nil {
		return nil, err
	}
	return &AbortEvidence{
		TranscriptHash: transcriptHash,
		Complaints:     []*dkgblame.Complaint{c},
		Disqualified: map[int]struct{}{
			fault.DealerIndex: {},
		},
	}, nil
}

// abortEvidenceWrap returns an error that carries the AbortEvidence
// behind a stable wrapper so the caller can extract it via errors.As.
func abortEvidenceWrap(ev *AbortEvidence, inner error) error {
	return &bootstrapAbortErr{ev: ev, inner: inner}
}

// bootstrapAbortErr is the error type that BootstrapPedersen returns
// when an identifiable abort is detected. The caller extracts the
// AbortEvidence via the package-level ExtractAbortEvidence helper.
type bootstrapAbortErr struct {
	ev    *AbortEvidence
	inner error
}

func (e *bootstrapAbortErr) Error() string {
	if e.inner == nil {
		return "keyera: bootstrap-pedersen aborted"
	}
	return e.inner.Error()
}

func (e *bootstrapAbortErr) Unwrap() error { return e.inner }

// ExtractAbortEvidence returns the AbortEvidence carried by an error
// returned by BootstrapPedersen / FinishBootstrapPedersen, or nil if the
// error does not carry one. Callers use this idiom:
//
//	era, transcript, err := keyera.BootstrapPedersen(...)
//	if ev := keyera.ExtractAbortEvidence(err); ev != nil {
//	    // commit ev to the chain, slash ev.Disqualified, stay at prev epoch.
//	}
//
// errors.As-style targeting is not supported because *AbortEvidence is
// not an error type and would force callers to define a wrapper
// interface; the helper is friendlier and equally explicit.
func ExtractAbortEvidence(err error) *AbortEvidence {
	if err == nil {
		return nil
	}
	var be *bootstrapAbortErr
	if !asBootstrapAbortErr(err, &be) {
		return nil
	}
	return be.ev
}

// asBootstrapAbortErr traverses the error tree (single + multi-error
// unwrap chains, mirroring Go 1.20+ errors.Is semantics) looking for our
// concrete abort type. We don't use errors.As directly because
// *bootstrapAbortErr is unexported and we want to keep it that way (the
// public surface is the AbortEvidence value, not the error wrapper).
func asBootstrapAbortErr(err error, out **bootstrapAbortErr) bool {
	if err == nil {
		return false
	}
	if be, ok := err.(*bootstrapAbortErr); ok {
		*out = be
		return true
	}
	if unwrap, ok := err.(interface{ Unwrap() error }); ok {
		if asBootstrapAbortErr(unwrap.Unwrap(), out) {
			return true
		}
	}
	if unwrap, ok := err.(interface{ Unwrap() []error }); ok {
		for _, e := range unwrap.Unwrap() {
			if asBootstrapAbortErr(e, out) {
				return true
			}
		}
	}
	return false
}

// pedersenNodeID returns the deterministic committee NodeID for index i. The
// first two bytes encode the 1-based position; the rest are a fixed domain tag
// byte. NodeIDs are public committee labels, not secrets.
func pedersenNodeID(i int) dkgchannel.NodeID {
	var id dkgchannel.NodeID
	binary.BigEndian.PutUint16(id[:2], uint16(i+1))
	id[2] = 0xC0
	return id
}

// derivedStream returns a deterministic unbounded byte stream from a domain tag
// and a 32-bit selector (party index). Used to seed channel identities and KEM
// randomness reproducibly.
func derivedStream(tag string, sel uint32) io.Reader {
	h := blake3.New()
	_, _ = h.Write([]byte(tag))
	_, _ = h.Write(u32be(sel))
	return h.Digest()
}

// seededRound1Rng returns the reader vss.Round1 consumes: the exact 32-byte
// sampling seed first (so the χ draws — hence commits and shares — match the
// prior dkg2 path byte-for-byte), then a deterministic KEM-randomness tail
// (which affects only the immediately-opened envelope ciphertext).
func seededRound1Rng(seed []byte, partyIndex int) io.Reader {
	return io.MultiReader(bytes.NewReader(seed), derivedStream(kemStreamTag, uint32(partyIndex)))
}

// u32be returns the 4-byte big-endian encoding of x.
func u32be(x uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], x)
	return b[:]
}

// serializeVector returns the canonical wire bytes of a vector via the
// lattigo WriteTo. Length-prefixed so concatenation is unambiguous.
func serializeVector(v structs.Vector[lring.Poly]) ([]byte, error) {
	var inner []byte
	buf := bytesBuffer{}
	if _, err := v.WriteTo(&buf); err != nil {
		return nil, err
	}
	inner = buf.Bytes()
	out := make([]byte, 4+len(inner))
	binary.BigEndian.PutUint32(out[:4], uint32(len(inner)))
	copy(out[4:], inner)
	return out, nil
}

// bTildeBytes returns the canonical wire bytes of the final bTilde.
func bTildeBytes(bTilde structs.Vector[lring.Poly]) []byte {
	buf := bytesBuffer{}
	if _, err := bTilde.WriteTo(&buf); err != nil {
		// WriteTo on a valid Vector cannot fail with a bytesBuffer.
		return nil
	}
	return buf.Bytes()
}

// framedJoin concatenates 32-byte digests with no inner separator (each
// digest is fixed-length, so the join is unambiguous). The hash suite's
// internal length-prefixing handles framing across the call.
func framedJoin(digests [][32]byte) []byte {
	out := make([]byte, 0, 32*len(digests))
	for _, d := range digests {
		out = append(out, d[:]...)
	}
	return out
}

// framedJoinValidators joins validator ID strings with 4-byte length
// prefixes (canonical wire framing — matches the suite's TranscriptHash
// internal framing convention).
func framedJoinValidators(validators []string) []byte {
	out := make([]byte, 0, 64)
	for _, v := range validators {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(v)))
		out = append(out, l[:]...)
		out = append(out, []byte(v)...)
	}
	return out
}

// framedJoinUint32 joins big-endian uint32 values.
func framedJoinUint32(vs []uint32) []byte {
	out := make([]byte, 4*len(vs))
	for i, v := range vs {
		binary.BigEndian.PutUint32(out[4*i:], v)
	}
	return out
}

// framedJoinBytes joins length-prefixed byte slices.
func framedJoinBytes(parts [][]byte) []byte {
	total := 0
	for _, p := range parts {
		total += 4 + len(p)
	}
	out := make([]byte, 0, total)
	for _, p := range parts {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(p)))
		out = append(out, l[:]...)
		out = append(out, p...)
	}
	return out
}

// bytesBuffer is a minimal io.Writer implementation used by
// serializeVector to avoid pulling in bytes.Buffer's full API surface.
type bytesBuffer struct{ b []byte }

func (b *bytesBuffer) Write(p []byte) (int, error) {
	b.b = append(b.b, p...)
	return len(p), nil
}

func (b *bytesBuffer) Bytes() []byte { return b.b }
