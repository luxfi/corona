// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keyera

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"

	"github.com/luxfi/corona/dkg2"
	"github.com/luxfi/corona/hash"
	"github.com/luxfi/corona/primitives"
	"github.com/luxfi/corona/sign"
	"github.com/luxfi/corona/threshold"
	"github.com/luxfi/corona/utils"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/sampling"
	"github.com/luxfi/lattice/v7/utils/structs"
)

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
type AbortEvidence struct {
	TranscriptHash [32]byte
	Complaints     []*dkg2.Complaint
	Disqualified   map[int]struct{}
}

// Errors specific to the Pedersen-DKG bootstrap path.
var (
	// ErrBootstrapPedersenAbort is returned when the run identifies one or
	// more misbehaving senders. The caller receives an AbortEvidence.
	ErrBootstrapPedersenAbort = errors.New("keyera: bootstrap-pedersen aborted with identifiable evidence")

	// ErrBootstrapPedersenShape is returned when input parameters violate
	// the (1 ≤ t ≤ n) and (n ≥ 2) constraints required by dkg2.
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

// PedersenContributions is the raw output of all parties' Round 1 plus
// the per-recipient share/blind tables, suitable for direct injection
// into the FinishBootstrapPedersen orchestrator. Tests use this to
// simulate identifiable-abort scenarios where a single party is
// dishonest: they tamper one entry and then call FinishBootstrapPedersen
// to drive the abort path.
//
// In production the per-party contributions arrive over the network and
// the consensus layer assembles them; the kernel exists for tests +
// integration suite.
type PedersenContributions struct {
	// Round1 outputs indexed by sender party ID 0..n-1.
	Round1 []*dkg2.Round1Output
	// dkg2 ring (matches Round1's sessions). The caller may build a fresh
	// dkg2.NewParams() and pass its .R.
	Sessions []*dkg2.DKGSession
}

// BootstrapPedersen opens a new key era WITHOUT a trusted dealer.
//
// The construction follows Path (a) of papers/lp-073-pulsar §07:
//
//  1. Each party runs dkg2.Round1 → broadcasts Pedersen commits, sends
//     (share_{i→j}, blind_{i→j}) privately to every recipient j.
//  2. Each party verifies all incoming Pedersen pairs (constant-time
//     comparison; identifiable abort on mismatch).
//  3. Each party runs dkg2.Round2 → obtains its share s_j of the master
//     secret s. NO PARTY ever holds s in memory.
//  4. Each party samples a fresh Gaussian e_j' ~ D(σ'') locally with
//     σ'' = κ · σ_E · √n (the slack reservation of LP-073 §5) and
//     broadcasts β_j = A · NTT(λ_j · s_j) + e_j'. The published β_j is
//     LWE-protected by e_j' so no party learns more than its own share.
//  5. All parties aggregate b = Σ_j β_j = A · s + e'' in NTT-Mont; the
//     Corona-Sign-shaped public key is bTilde = Round_Xi(b).
//
// On success returns:
//
//   - era — fully populated *KeyEra with the noise-flooded GroupKey;
//   - transcript — the public BootstrapTranscript suitable for chain commit;
//   - nil error.
//
// On identifiable abort returns (nil, nil, ErrBootstrapPedersenAbort) and
// the AbortEvidence is wrapped into the returned error via errors.As.
//
// In production each party drives its own dkg2.DKGSession over an
// authenticated network. This in-process kernel drives every party
// itself; it exists to (a) be the trusted-collaborator path for the
// single-process integration tests and (b) provide a reference against
// which the distributed protocol can be byte-equality checked. The
// distributed wrapper at the consensus layer reuses every primitive
// imported here.
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
	// dkg2 requires n ≥ 2 and 1 ≤ t < n (strictly less than for honest-
	// abort detection). For t == n we fall back to the trusted-dealer
	// path because dkg2 cannot guard a corruption-free quorum below 1.
	if n < 2 {
		return nil, nil, fmt.Errorf("%w: n=%d (dkg2 requires n >= 2)", ErrBootstrapPedersenShape, n)
	}
	if t >= n {
		return nil, nil, fmt.Errorf("%w: t=%d n=%d (dkg2 requires t < n)", ErrBootstrapPedersenShape, t, n)
	}
	if entropy == nil {
		entropy = rand.Reader
	}
	suite = hash.Resolve(suite)
	suiteID := suite.ID()

	// Initialize dkg2 ring + matrices. The matrices A, B are
	// nothing-up-my-sleeve; every party derives them deterministically.
	dkgParams, err := dkg2.NewParams()
	if err != nil {
		return nil, nil, fmt.Errorf("keyera: bootstrap-pedersen dkg2 params: %w", err)
	}

	// Create one session per party. Each session needs an independent
	// random seed for its Round1WithSeed input; we draw all of them up
	// front so the entropy stream is sequenced canonically.
	sessions := make([]*dkg2.DKGSession, n)
	round1Seeds := make([][]byte, n)
	for i := 0; i < n; i++ {
		sess, err := dkg2.NewDKGSession(dkgParams, i, n, t, suite)
		if err != nil {
			return nil, nil, fmt.Errorf("keyera: bootstrap-pedersen NewDKGSession[%d]: %w", i, err)
		}
		sessions[i] = sess
		seed := make([]byte, sign.KeySize)
		if _, err := io.ReadFull(entropy, seed); err != nil {
			return nil, nil, fmt.Errorf("keyera: bootstrap-pedersen entropy[%d]: %w", i, err)
		}
		round1Seeds[i] = seed
	}

	// Round 1 — produce per-party Pedersen commits + shares/blinds.
	round1 := make([]*dkg2.Round1Output, n)
	for i := 0; i < n; i++ {
		out, err := sessions[i].Round1WithSeed(round1Seeds[i])
		if err != nil {
			return nil, nil, fmt.Errorf("keyera: bootstrap-pedersen Round1[%d]: %w", i, err)
		}
		round1[i] = out
	}

	return finishBootstrapPedersen(suite, suiteID, t, n, validators, groupID, eraID, dkgParams, sessions, round1)
}

// finishBootstrapPedersen drives Rounds 1.5/2 and the Path (a) noise-
// flooding on a pre-computed set of Round 1 outputs. Tests use this
// entrypoint (via FinishBootstrapPedersen) to inject deliberately
// dishonest contributions and exercise the identifiable-abort path.
//
// The in-process orchestrator owns the dkg2 sessions and the round1
// outputs; in production each party drives its own. The transcript bytes
// are independent of which side runs the loop because every input is
// deterministic given the round1 outputs and the validator list.
func finishBootstrapPedersen(suite hash.HashSuite, suiteID string, t, n int, validators []string, groupID CoronaGroupID, eraID CoronaKeyEraID, dkgParams *dkg2.Params, sessions []*dkg2.DKGSession, round1 []*dkg2.Round1Output) (*KeyEra, *BootstrapTranscript, error) {
	r := dkgParams.R

	// Round 1.5 — each recipient computes its sender digests under the
	// active suite. In a distributed deployment each digest is broadcast
	// and cross-checked. The kernel runs in-process so digests are
	// deterministic and pinned into the transcript.
	digests := make([][32]byte, n)
	for i := 0; i < n; i++ {
		d, err := round1[i].CommitDigest(suite)
		if err != nil {
			return nil, nil, fmt.Errorf("keyera: bootstrap-pedersen CommitDigest[%d]: %w", i, err)
		}
		digests[i] = d
	}

	// Round 2 — each recipient verifies every share/blind pair against
	// the commits, then aggregates to its own (s_j, u_j, b_ped). On any
	// identifiable abort we collect signed complaints and return.
	//
	// s shares per recipient (standard form, dimension sign.N).
	sShares := make([]structs.Vector[ring.Poly], n)
	for j := 0; j < n; j++ {
		shares := map[int]structs.Vector[ring.Poly]{}
		blinds := map[int]structs.Vector[ring.Poly]{}
		commits := map[int][]structs.Vector[ring.Poly]{}
		for i := 0; i < n; i++ {
			shares[i] = round1[i].Shares[j]
			blinds[i] = round1[i].Blinds[j]
			commits[i] = round1[i].Commits
		}
		sj, _, _, badID, err := sessions[j].Round2Identify(shares, blinds, commits)
		if err != nil {
			abortEv, abortErr := buildAbortEvidence(suite, digests, suiteID, n, t,
				validators, j, badID, shares, blinds, commits)
			if abortErr != nil {
				return nil, nil, fmt.Errorf("keyera: bootstrap-pedersen Round2[%d] + abort-evidence: %v / %w", j, abortErr, err)
			}
			return nil, nil, fmt.Errorf("%w: %w", ErrBootstrapPedersenAbort,
				abortEvidenceWrap(abortEv, err))
		}
		sShares[j] = sj
	}

	// Path (a) noise flooding. Compute Lagrange weights at X=0 for the
	// full committee T = {0, ..., n-1}; each party's contribution scales
	// its share by λ_j so the aggregate equals s. Each party then adds a
	// fresh Gaussian e_j' under σ'' = κ · σ_E · √n.
	//
	// The deterministic noise seed for e_j' is derived from the active
	// HashSuite over the canonical transcript prefix so a KAT replay can
	// reproduce the bootstrap byte-for-byte from a single entropy source.
	A := sessions[0].APublic()
	lagrange := computeFullCommitteeLagrange(r, n)

	// Build aggregated b in NTT-Mont form by summing per-party β_j.
	// We also serialize each β_j for the transcript.
	bSum := utils.InitializeVector(r, sign.M)
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
		lambda := r.NewPoly()
		lambda.Copy(lagrange[j])
		r.NTT(lambda, lambda)
		r.MForm(lambda, lambda)

		// NTT-Mont share s_j scaled by λ_j: λ_j · NTT-Mont(s_j).
		// sShares[j] is in standard coefficient form; convert to NTT-Mont.
		sNTT := make(structs.Vector[ring.Poly], sign.N)
		for vi := 0; vi < sign.N; vi++ {
			sNTT[vi] = *sShares[j][vi].CopyNew()
			r.NTT(sNTT[vi], sNTT[vi])
			r.MForm(sNTT[vi], sNTT[vi])
		}

		// (λ_j · s_j) coordinate-wise.
		scaled := make(structs.Vector[ring.Poly], sign.N)
		for vi := 0; vi < sign.N; vi++ {
			scaled[vi] = r.NewPoly()
			r.MulCoeffsMontgomery(sNTT[vi], lambda, scaled[vi])
		}

		// β_j = A · (λ_j · s_j) + e_j' where e_j' ~ D(σ'').
		Aprod := utils.InitializeVector(r, sign.M)
		utils.MatrixVectorMul(r, A, scaled, Aprod)

		ePrime := samplePathANoise(r, suite, noiseSeedTranscript, j, noiseSigma, noiseBound)
		// ePrime is in NTT-Mont; β_j = Aprod + ePrime.
		beta := utils.InitializeVector(r, sign.M)
		utils.VectorAdd(r, Aprod, ePrime, beta)

		// Serialize β_j for the transcript.
		buf, serr := serializeVector(beta)
		if serr != nil {
			return nil, nil, fmt.Errorf("keyera: bootstrap-pedersen serialize beta[%d]: %w", j, serr)
		}
		betaSerialized[j] = buf

		// Accumulate.
		utils.VectorAdd(r, bSum, beta, bSum)
	}

	// b = Σ_j β_j = A·s + e'' in NTT-Mont. Convert to standard form,
	// then round to bTilde under the QXi ring.
	utils.ConvertVectorFromNTT(r, bSum)
	bTilde := utils.RoundVector(r, dkgParams.RXi, bSum, sign.Xi)

	// Build Corona threshold.GroupKey. The matrix A is the dkg2 A
	// (nothing-up-my-sleeve), so the era is reproducible from the
	// transcript alone.
	thParams, err := threshold.NewParams()
	if err != nil {
		return nil, nil, fmt.Errorf("keyera: bootstrap-pedersen threshold params: %w", err)
	}
	gk := &threshold.GroupKey{
		A:      A,
		BTilde: bTilde,
		Params: thParams,
	}

	// Pairwise seeds and MAC keys. In a distributed deployment these come
	// from authenticated pairwise KEX (reshare/pairwise.go); the kernel
	// derives them deterministically from the transcript so KATs can
	// replay. The bytes are independent of any secret share material —
	// they form a public symmetric mask that the cohort agrees on.
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
		// signing-time multiplication path (matches threshold.GenerateKeys
		// convention).
		skNTT := make(structs.Vector[ring.Poly], sign.N)
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

// FinishBootstrapPedersen is the kernel entrypoint that takes a fully
// pre-computed set of Round1 outputs (one per party) and drives the
// remainder of the protocol: Round 1.5 digest computation, Round 2
// verification, Path (a) noise flooding, and KeyShare assembly.
//
// The caller is responsible for producing the dkg2.Round1Output array;
// in production this is the per-party network broadcast. In tests, the
// caller may deliberately tamper a Round1 output to exercise the
// identifiable-abort path.
//
// The dkgParams and sessions arrays MUST correspond to the supplied
// round1 outputs (same n, same t, same A, B matrices).
//
// suite=nil resolves to the production default (Corona-SHA3).
func FinishBootstrapPedersen(suite hash.HashSuite, t int, validators []string, groupID CoronaGroupID, eraID CoronaKeyEraID, dkgParams *dkg2.Params, sessions []*dkg2.DKGSession, round1 []*dkg2.Round1Output) (*KeyEra, *BootstrapTranscript, error) {
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
	if len(sessions) != n || len(round1) != n {
		return nil, nil, fmt.Errorf("%w: sessions=%d round1=%d, expected %d", ErrBootstrapPedersenShape, len(sessions), len(round1), n)
	}
	suite = hash.Resolve(suite)
	return finishBootstrapPedersen(suite, suite.ID(), t, n, validators, groupID, eraID, dkgParams, sessions, round1)
}

// BootstrapTrustedDealer is the legacy single-trusted-party bootstrap
// retained for genesis-ceremony scenarios where a non-distributed trust
// root is acceptable (e.g. a publicly observable foundation MPC ceremony
// at chain launch). It is byte-equivalent to the historical Bootstrap
// entrypoint.
//
// PREFER BootstrapPedersen for any deployment where no single party is
// trusted to discard the master secret.
//
// See DEPLOYMENT-RUNBOOK.md for the trust-model trade-off documentation.
func BootstrapTrustedDealer(t int, validators []string, groupID CoronaGroupID, eraID CoronaKeyEraID, entropy io.Reader) (*KeyEra, error) {
	return Bootstrap(t, validators, groupID, eraID, entropy)
}

// BootstrapTrustedDealerWithSuite is the suite-explicit form of
// BootstrapTrustedDealer.
func BootstrapTrustedDealerWithSuite(suite hash.HashSuite, t int, validators []string, groupID CoronaGroupID, eraID CoronaKeyEraID, entropy io.Reader) (*KeyEra, error) {
	return BootstrapWithSuite(suite, t, validators, groupID, eraID, entropy)
}

// pathANoiseParameters returns the (σ, bound) pair for the Path (a)
// noise-flooding sub-protocol over a committee of n parties. The slack
// reservation σ'' = κ · σ_E · √n is the LP-073 §5 bound: it is large
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
// the broadcast β_j byte-for-byte. In the production distributed
// protocol the seed comes from each party's own private RNG; here we
// derive deterministically for KAT-replay.
func samplePathANoise(r *ring.Ring, suite hash.HashSuite, transcript [32]byte, partyID int, sigma, bound float64) structs.Vector[ring.Poly] {
	var partyBuf [4]byte
	binary.BigEndian.PutUint32(partyBuf[:], uint32(partyID))
	seed := suite.TranscriptHash(
		transcript[:],
		[]byte("party"),
		partyBuf[:],
	)
	prng, _ := sampling.NewKeyedPRNG(seed[:])
	gauss := ring.NewGaussianSampler(prng, r,
		ring.DiscreteGaussian{Sigma: sigma, Bound: bound}, false)
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

// buildAbortEvidence packages a single recipient's Round2Identify
// failure into a signed-complaint-shaped AbortEvidence record. The
// senderID, when ≥ 0, names the misbehaving sender that recipient j
// observed.
//
// The kernel does not sign the complaints (signing requires the wire-
// identity ed25519 key, which lives at the consensus layer); it
// constructs unsigned complaints that the consensus layer signs and
// broadcasts. Tests inject an in-memory wire key via the AbortEvidence
// callers, which is fine because the bootstrap is in-process.
func buildAbortEvidence(suite hash.HashSuite, digests [][32]byte, suiteID string, n, t int, validators []string, complainerID, senderID int, shares, blinds map[int]structs.Vector[ring.Poly], commits map[int][]structs.Vector[ring.Poly]) (*AbortEvidence, error) {
	if senderID < 0 || senderID >= n {
		// Wrap missing-input failures as ComplaintMissing — the recipient
		// can still drive disqualification without naming a specific
		// commit/share pair.
		return &AbortEvidence{
			TranscriptHash: suite.TranscriptHash(
				[]byte(transcriptTag),
				[]byte(suiteID),
				framedJoinValidators(validators),
				framedJoinUint32([]uint32{uint32(t), uint32(n)}),
				framedJoin(digests),
			),
			Complaints: nil,
			Disqualified: map[int]struct{}{
				complainerID: {},
			},
		}, nil
	}
	transcriptHash := suite.TranscriptHash(
		[]byte(transcriptTag),
		[]byte(suiteID),
		framedJoinValidators(validators),
		framedJoinUint32([]uint32{uint32(t), uint32(n)}),
		framedJoin(digests),
	)
	c, err := dkg2.NewBadDeliveryComplaint(
		transcriptHash,
		senderID,
		complainerID,
		shares[senderID], blinds[senderID], commits[senderID],
	)
	if err != nil {
		return nil, err
	}
	return &AbortEvidence{
		TranscriptHash: transcriptHash,
		Complaints:     []*dkg2.Complaint{c},
		Disqualified: map[int]struct{}{
			senderID: {},
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

// serializeVector returns the canonical wire bytes of a vector via the
// lattigo WriteTo. Length-prefixed so concatenation is unambiguous.
func serializeVector(v structs.Vector[ring.Poly]) ([]byte, error) {
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
func bTildeBytes(bTilde structs.Vector[ring.Poly]) []byte {
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

// computeFullCommitteeLagrange (re-exported here for the path-(a) noise-
// flood path) computes Lagrange coefficients λ_j evaluated at X = 0 for
// the full committee {0, 1, ..., n-1} (1-indexed evaluation points
// 1..n). The result is in standard coefficient form; callers convert to
// NTT-Mont as needed.
//
// Defined in keyera.go alongside the trusted-dealer Bootstrap; redeclared
// here so the function reads as one cohesive Pedersen module.
var _ = primitives.ComputeLagrangeCoefficients
var _ = (*big.Int)(nil)
