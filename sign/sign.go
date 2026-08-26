package sign

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"io"
	"math/big"

	"github.com/luxfi/corona/hash"
	"github.com/luxfi/corona/primitives"
	"github.com/luxfi/corona/utils"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/sampling"
	"github.com/luxfi/lattice/v7/utils/structs"
)

// ErrDegenerateSession is returned by SignRound1 when the derived
// session identifier or the fresh hedge salt is all-zero. Both are
// fail-closed preconditions: an all-zero SessionID indicates an
// uninitialised/degenerate (sid, T), and an all-zero salt indicates the
// nonce-randomness source returned no entropy. Signing under either
// would forfeit the per-signature nonce-freshness on which the no-leak
// property rests, so the kernel refuses to proceed.
var ErrDegenerateSession = errors.New("corona/sign: degenerate session (zero SessionID or zero nonce salt); refusing to sign")

// Party struct holds all state and methods for a party in the protocol.
//
// Suite is the hash profile this party uses for every primitives.* call.
// NewParty defaults it to hash.Default() (Corona-SHA3). Operators that need
// to interoperate with old transcripts can override with NewCoronaBLAKE3().
type Party struct {
	ID             int
	Ring           *ring.Ring
	RingXi         *ring.Ring
	RingNu         *ring.Ring
	UniformSampler *ring.UniformSampler
	SkShare        structs.Vector[ring.Poly]
	Seed           map[int][][]byte
	R              structs.Matrix[ring.Poly]
	C              ring.Poly
	H              structs.Vector[ring.Poly]
	Lambda         ring.Poly
	D              structs.Matrix[ring.Poly]
	MACKeys        map[int][]byte
	MACs           map[int][]byte
	Suite          hash.HashSuite

	// Rand is the source of the fresh per-signature nonce hedge salt
	// drawn in SignRound1. NewPartyWithSuite defaults it to
	// crypto/rand.Reader, which is what every production signer uses.
	// KAT/oracle and cross-path byte-equality harnesses pin it to a
	// deterministic reader so the signature bytes are reproducible; no
	// other code path should override it. This is the single seam
	// between hedged (production) and deterministic (test) signing —
	// mirroring threshold.GenerateKeys' randSource parameter.
	Rand io.Reader
}

// NewParty initializes a new Party instance with the production hash suite
// (Corona-SHA3). To use a different suite, set Party.Suite after construction
// or call NewPartyWithSuite.
func NewParty(id int, r *ring.Ring, r_xi *ring.Ring, r_nu *ring.Ring, sampler *ring.UniformSampler) *Party {
	return NewPartyWithSuite(id, r, r_xi, r_nu, sampler, hash.Default())
}

// NewPartyWithSuite initializes a Party with an explicit hash suite. Pass
// nil to resolve to the production default at call time.
func NewPartyWithSuite(id int, r *ring.Ring, r_xi *ring.Ring, r_nu *ring.Ring, sampler *ring.UniformSampler, suite hash.HashSuite) *Party {
	return &Party{
		ID:             id,
		Ring:           r,
		RingXi:         r_xi,
		RingNu:         r_nu,
		UniformSampler: sampler,
		MACKeys:        make(map[int][]byte),
		MACs:           make(map[int][]byte),
		Suite:          hash.Resolve(suite),
		Rand:           rand.Reader,
	}
}

// Gen generates the secret shares, seeds, MAC keys, and the public parameter b
func Gen(r *ring.Ring, r_xi *ring.Ring, uniformSampler *ring.UniformSampler, trustedDealerKey []byte, lagrangeCoefficients structs.Vector[ring.Poly]) (structs.Matrix[ring.Poly], map[int]structs.Vector[ring.Poly], map[int][][]byte, map[int]map[int][]byte, structs.Vector[ring.Poly]) {
	A := utils.SamplePolyMatrix(r, M, N, uniformSampler, true, true)

	precomputeSize := (K * K * KeySize) + (r.N() * N * (K - 1) * len(r.Modulus().Bytes())) + (K * (K - 1) * KeySize)
	utils.PrecomputeRandomness(precomputeSize, trustedDealerKey)

	prng, _ := sampling.NewKeyedPRNG(trustedDealerKey)
	gaussianParams := ring.DiscreteGaussian{Sigma: SigmaE, Bound: BoundE}
	gaussianSampler := ring.NewGaussianSampler(prng, r, gaussianParams, false)

	s := utils.SamplePolyVector(r, N, gaussianSampler, false, false)
	skShares := primitives.ShamirSecretSharing(r, s, Threshold, lagrangeCoefficients)

	for _, skShare := range skShares {
		utils.ConvertVectorToNTT(r, skShare)
	}
	utils.ConvertVectorToNTT(r, s)

	e := utils.SamplePolyVector(r, M, gaussianSampler, true, true)
	b := utils.InitializeVector(r, M)
	utils.MatrixVectorMul(r, A, s, b)
	utils.VectorAdd(r, b, e, b)

	// Round b
	utils.ConvertVectorFromNTT(r, b)
	bTilde := utils.RoundVector(r, r_xi, b, Xi)

	seeds := make(map[int][][]byte)
	MACKeys := make(map[int]map[int][]byte)
	MACKeys[0] = make(map[int][]byte)

	for i := 0; i < K; i++ {
		seeds[i] = make([][]byte, K)
		for j := 0; j < K; j++ {
			seeds[i][j] = utils.GetRandomBytes(KeySize)
			if i != j {
				if MACKeys[j] == nil {
					MACKeys[j] = make(map[int][]byte)
				}
				if MACKeys[i][j] == nil && MACKeys[j][i] == nil {
					MACKeys[i][j] = utils.GetRandomBytes(KeySize)
					MACKeys[j][i] = MACKeys[i][j]
				}
			}
		}
	}

	return A, skShares, seeds, MACKeys, bTilde
}

// SignRound1 performs the first round of signing.
//
// PRECONDITION (HARD, consensus-enforced): the caller MUST supply an sid
// that is unique for this signer's skShare across the lifetime of that
// share. In the Quasar deployment sid is the consensus slot/round and
// slot-uniqueness is a chain invariant (LP-020). This kernel does NOT
// trust that invariant for its no-leak guarantee: the nonce key is
// additionally hedged with fresh per-signature randomness drawn from
// party.Rand (default crypto/rand), so reuse of an sid degrades only the
// defence-in-depth layer, not the security proof. An obviously-degenerate
// session (zero derived SessionID, or a randomness source that yields a
// zero salt) is rejected fail-closed with ErrDegenerateSession.
//
// The error return is the fail-closed signal; on error the returned D
// and MACs are nil and the caller MUST abort the signing session.
func (party *Party) SignRound1(A structs.Matrix[ring.Poly], sid int, PRFKey []byte, T []int) (structs.Matrix[ring.Poly], map[int][]byte, error) {
	r := party.Ring

	// Nonce-key derivation (replaces the CRIT-1 bare-int keying).
	//   1. sessionID: full-width (no 64-bit truncation) deterministic
	//      binding to the consensus-agreed (sid, T).
	//   2. salt: fresh 256-bit per-signature randomness — hedged signing.
	// PRNGKeyForRound = PRF(skShare, "CoronaNonceV3" || sessionID || salt).
	// Either input being all-zero is a degenerate session: fail closed
	// rather than sign with forfeited nonce freshness.
	sessionID := primitives.DeriveSessionID(party.Suite, sid, T)
	if isZero32(sessionID) {
		return nil, nil, ErrDegenerateSession
	}
	src := party.Rand
	if src == nil {
		src = rand.Reader
	}
	var salt [primitives.SessionIDSize]byte
	if _, err := io.ReadFull(src, salt[:]); err != nil {
		return nil, nil, err
	}
	if isZero32(salt) {
		return nil, nil, ErrDegenerateSession
	}
	skHash := primitives.PRNGKeyForRound(party.Suite, party.SkShare, sessionID, salt)
	prng, _ := sampling.NewKeyedPRNG(skHash)
	gaussianParams := ring.DiscreteGaussian{Sigma: SigmaStar, Bound: BoundStar}
	gaussianSampler := ring.NewGaussianSampler(prng, r, gaussianParams, false)
	r_star := utils.SamplePolyVector(r, N, gaussianSampler, true, true)
	e_star := utils.SamplePolyVector(r, M, gaussianSampler, true, true)

	// Initialize R_i and E_i
	gaussianParams = ring.DiscreteGaussian{Sigma: SigmaE, Bound: BoundE}
	gaussianSampler = ring.NewGaussianSampler(prng, r, gaussianParams, false)
	R_i := utils.SamplePolyMatrix(r, N, Dbar, gaussianSampler, true, true)
	E_i := utils.SamplePolyMatrix(r, M, Dbar, gaussianSampler, true, true)

	concatenatedR := utils.InitializeMatrix(r, N, Dbar+1)
	for i := range concatenatedR {
		concatenatedR[i] = append([]ring.Poly{r_star[i]}, R_i[i]...)
	}
	party.R = concatenatedR

	// Ensure concatenatedE is properly initialized
	concatenatedE := utils.InitializeMatrix(r, M, Dbar+1)
	for i := range concatenatedE {
		concatenatedE[i] = append([]ring.Poly{e_star[i]}, E_i[i]...)
	}

	D := utils.InitializeMatrix(r, M, Dbar+1)

	utils.MatrixMatrixMul(r, A, concatenatedR, D)
	if err := utils.MatrixAdd(r, concatenatedE, D, D); err != nil {
		return nil, nil, err
	}

	party.D = D

	// Generate MACs for each party
	MACs := make(map[int][]byte)
	for _, j := range T {
		if j != party.ID {
			MACs[j] = primitives.GenerateMAC(party.Suite, D, party.MACKeys[j], party.ID, sid, T, j, false)
		}
	}

	return D, MACs, nil
}

// nonceSaltDomain domain-separates the deterministic nonce-salt stream
// from every other use of a KeyedPRNG seeded by the same dealer seed.
var nonceSaltDomain = []byte("corona.sign.nonce-salt.v1")

// DeterministicNonceSource returns a deterministic, party-distinct
// io.Reader suitable for Party.Rand in KAT/oracle and cross-path
// byte-equality harnesses. It is keyed by the dealer seed, a fixed
// domain tag, and the party index, so each party draws an independent
// but reproducible hedge salt. Production signers MUST NOT use this —
// they keep the default crypto/rand.Reader. This is the single
// canonical way to pin hedged signing to a reproducible stream.
func DeterministicNonceSource(seed []byte, partyIndex int) io.Reader {
	key := make([]byte, 0, len(seed)+len(nonceSaltDomain)+4)
	key = append(key, seed...)
	key = append(key, nonceSaltDomain...)
	key = append(key, byte(partyIndex>>24), byte(partyIndex>>16), byte(partyIndex>>8), byte(partyIndex))
	prng, err := sampling.NewKeyedPRNG(key)
	if err != nil {
		// NewKeyedPRNG only errors on BLAKE2 XOF construction, which
		// cannot fail for a non-nil key. Surface loudly if the upstream
		// contract ever changes rather than return a nil reader.
		panic("corona/sign: DeterministicNonceSource: " + err.Error())
	}
	return prng
}

// isZero32 reports whether a 32-byte array is all-zero, in constant time.
// Used by the SignRound1 fail-closed guard; the operands (a derived
// SessionID, a freshly drawn salt) are not adversary-chosen, but a
// branch-free check keeps the guard uniform and free of a data-dependent
// early exit.
func isZero32(b [primitives.SessionIDSize]byte) bool {
	var zero [primitives.SessionIDSize]byte
	return subtle.ConstantTimeCompare(b[:], zero[:]) == 1
}

// SignRound2Preprocess verifies the MACs received in round 1 and performs the minimum eigenvalue check
func (party *Party) SignRound2Preprocess(A structs.Matrix[ring.Poly], b structs.Vector[ring.Poly], D map[int]structs.Matrix[ring.Poly], MACs map[int]map[int][]byte, sid int, T []int) (bool, structs.Matrix[ring.Poly], []byte) {
	transcriptHash := primitives.Hash(party.Suite, A, b, D, sid, T)

	for _, j := range T {
		if j != party.ID {
			MAC := MACs[j][party.ID]
			expectedMAC := primitives.GenerateMAC(party.Suite, D[j], party.MACKeys[j], party.ID, sid, T, j, true)
			// Constant-time so a peer probing MACs cannot learn the matching prefix
			// length from the comparison's timing. MAC length is fixed and public.
			if subtle.ConstantTimeCompare(MAC, expectedMAC) != 1 {
				return false, nil, nil
			}
		}
	}

	DSum := utils.InitializeMatrix(party.Ring, M, Dbar+1)
	// Range T, not the whole map. The MAC loop above authenticates only the
	// entries named by T; ranging D folded in every commitment a peer sent,
	// including one keyed by a party id outside T that no MAC ever checked. A
	// non-member's matrix — of any shape, since nothing validated it — then
	// reached the adder, where its shape decides what gets allocated.
	for _, j := range T {
		D_j, ok := D[j]
		if !ok {
			return false, nil, nil
		}
		if err := utils.MatrixAdd(party.Ring, D_j, DSum, DSum); err != nil {
			return false, nil, nil
		}
	}

	if !FullRankCheck(DSum, party.Ring) {
		return false, nil, nil
	}

	return true, DSum, transcriptHash
}

// SignRound2 performs the second round of signing.
//
// transcriptHash is the digest returned by SignRound2Preprocess; it
// binds (A, b, D, sid, T) under the active hash suite.
func (party *Party) SignRound2(A structs.Matrix[ring.Poly], bTilde structs.Vector[ring.Poly], DSum structs.Matrix[ring.Poly], sid int, mu string, T []int, PRFKey []byte, transcriptHash []byte) structs.Vector[ring.Poly] {
	r := party.Ring
	r_nu := party.RingNu
	partyID := party.ID
	concatR := party.R
	seeds := party.Seed

	s_i := party.SkShare
	lambda := party.Lambda

	onePoly := r.NewMonomialXi(0)
	r.NTT(onePoly, onePoly)
	r.MForm(onePoly, onePoly)

	u := structs.Vector[ring.Poly]{}
	oneSlice := structs.Vector[ring.Poly]{onePoly}
	if Dbar > 0 {
		h_u := primitives.GaussianHash(party.Suite, r, transcriptHash, mu, SigmaU, BoundU, Dbar)
		u = append(oneSlice, h_u...)
	}

	h := utils.InitializeVector(r, M)
	utils.MatrixVectorMul(r, DSum, u, h)

	utils.ConvertVectorFromNTT(r, h)
	roundedH := utils.RoundVector(r, r_nu, h, Nu)
	party.H = roundedH

	c := primitives.LowNormHash(party.Suite, r, A, bTilde, roundedH, mu, Kappa)
	party.C = c

	seed_i := party.Seed[party.ID]
	mask := utils.InitializeVector(r, N)
	for _, j := range T {
		mask_j := primitives.PRF(party.Suite, r, seed_i[j], PRFKey, mu, transcriptHash, N)
		utils.VectorAdd(r, mask, mask_j, mask)
	}

	maskPrime := utils.InitializeVector(r, N)
	for _, j := range T {
		mask_j := primitives.PRF(party.Suite, r, seeds[j][partyID], PRFKey, mu, transcriptHash, N)
		utils.VectorAdd(r, maskPrime, mask_j, maskPrime)
	}

	z_i := utils.InitializeVector(r, N)

	utils.MatrixVectorMul(r, concatR, u, z_i)

	utils.VectorAdd(r, z_i, maskPrime, z_i)

	s_c_lambda := utils.InitializeVector(r, N)

	utils.VectorPolyMul(r, s_i, lambda, s_c_lambda)
	utils.VectorPolyMul(r, s_c_lambda, c, s_c_lambda)
	utils.VectorAdd(r, z_i, s_c_lambda, z_i)
	utils.VectorSub(r, z_i, mask, z_i)

	return z_i
}

// SignFinalize finalizes the signature
func (party *Party) SignFinalize(z map[int]structs.Vector[ring.Poly], A structs.Matrix[ring.Poly], bTilde structs.Vector[ring.Poly]) (ring.Poly, structs.Vector[ring.Poly], structs.Vector[ring.Poly]) {
	r := party.Ring
	r_xi := party.RingXi
	r_nu := party.RingNu
	c := party.C
	h := party.H

	z_sum := utils.InitializeVector(r, N)

	for _, z_j := range z {
		utils.VectorAdd(r, z_sum, z_j, z_sum)
	}

	Az_bc := utils.InitializeVector(r, M)
	utils.MatrixVectorMul(r, A, z_sum, Az_bc)
	bc := utils.InitializeVector(r, M)

	b := utils.RestoreVector(r, r_xi, bTilde, Xi)
	utils.ConvertVectorToNTT(r, b)

	utils.VectorPolyMul(r, b, c, bc)
	utils.VectorSub(r, Az_bc, bc, Az_bc)

	utils.ConvertVectorFromNTT(r, Az_bc)
	roundedAz_bc := utils.RoundVector(r, r_nu, Az_bc, Nu)

	Delta := utils.InitializeVector(r_nu, M)
	utils.VectorSub(r_nu, h, roundedAz_bc, Delta)

	return party.C, z_sum, Delta
}

// Verify verifies the correctness of the signature using the production
// hash suite (Corona-SHA3). For non-default suites use VerifyWithSuite.
// Note: This function does not modify its inputs - it creates copies where needed.
func Verify(r *ring.Ring, r_xi *ring.Ring, r_nu *ring.Ring, z structs.Vector[ring.Poly], A structs.Matrix[ring.Poly], mu string, bTilde structs.Vector[ring.Poly], c ring.Poly, roundedDelta structs.Vector[ring.Poly]) bool {
	return VerifyWithSuite(nil, r, r_xi, r_nu, z, A, mu, bTilde, c, roundedDelta)
}

// VerifyWithSuite is the suite-explicit form of Verify. suite=nil resolves
// to the production default (Corona-SHA3).
func VerifyWithSuite(suite hash.HashSuite, r *ring.Ring, r_xi *ring.Ring, r_nu *ring.Ring, z structs.Vector[ring.Poly], A structs.Matrix[ring.Poly], mu string, bTilde structs.Vector[ring.Poly], c ring.Poly, roundedDelta structs.Vector[ring.Poly]) bool {
	// A signature verifies only at the exact dimensions the key implies: A is the
	// M-row public matrix, z has one polynomial per column, and Delta has M. Below,
	// MatrixVectorMul reads z over the columns and VectorAdd reads Delta over M, so
	// without this guard a longer z or Delta leaves a fixed prefix verifying while
	// the appended polynomials are ignored — a second byte string that verifies for
	// one key and message — and a shorter one indexes past its end and panics on
	// the bus surface. Deriving the column count from A keeps the check exact for
	// whatever shape the key declares.
	if len(A) != M || len(roundedDelta) != M {
		return false
	}
	cols := len(A[0])
	for i := range A {
		if len(A[i]) != cols {
			return false
		}
	}
	if len(z) != cols {
		return false
	}

	// Make a copy of z to avoid modifying the input signature
	zCopy := make(structs.Vector[ring.Poly], len(z))
	for i := range z {
		zCopy[i] = *z[i].CopyNew()
	}

	Az_bc := utils.InitializeVector(r, M)
	utils.MatrixVectorMul(r, A, zCopy, Az_bc)
	bc := utils.InitializeVector(r, M)

	b := utils.RestoreVector(r, r_xi, bTilde, Xi)
	utils.ConvertVectorToNTT(r, b)

	utils.VectorPolyMul(r, b, c, bc)
	utils.VectorSub(r, Az_bc, bc, Az_bc)

	utils.ConvertVectorFromNTT(r, Az_bc)
	roundedAz_bc := utils.RoundVector(r, r_nu, Az_bc, Nu)

	Az_bc_Delta := utils.InitializeVector(r_nu, M)
	utils.VectorAdd(r_nu, roundedAz_bc, roundedDelta, Az_bc_Delta)

	computedC := primitives.LowNormHash(suite, r, A, bTilde, Az_bc_Delta, mu, Kappa)
	if !r.Equal(c, computedC) {
		return false
	}

	Delta := utils.RestoreVector(r, r_nu, roundedDelta, Nu)
	utils.ConvertVectorFromNTT(r, zCopy)

	return CheckL2Norm(r, Delta, zCopy)
}

// CheckL2Norm checks if the L2 norm of the vector of Delta is less than or equal to Bsquare
func CheckL2Norm(r *ring.Ring, Delta structs.Vector[ring.Poly], z structs.Vector[ring.Poly]) bool {
	sumSquares := big.NewInt(0)
	qBig := new(big.Int).SetUint64(Q)
	halfQ := new(big.Int).Div(qBig, big.NewInt(2))

	DeltaCoeffsBigInt := make(structs.Vector[[]*big.Int], r.N())
	for i, polyCoeffs := range Delta {
		DeltaCoeffsBigInt[i] = make([]*big.Int, r.N())
		r.PolyToBigint(polyCoeffs, 1, DeltaCoeffsBigInt[i])
	}

	for _, polyCoeffs := range DeltaCoeffsBigInt {
		for _, coeff := range polyCoeffs {
			if coeff.Cmp(halfQ) > 0 {
				coeff.Sub(coeff, qBig)
			}
			coeffSquare := new(big.Int).Mul(coeff, coeff)
			sumSquares.Add(sumSquares, coeffSquare)
		}
	}

	zCoeffsBigInt := make(structs.Vector[[]*big.Int], r.N())
	for i, polyCoeffs := range z {
		zCoeffsBigInt[i] = make([]*big.Int, r.N())
		r.PolyToBigint(polyCoeffs, 1, zCoeffsBigInt[i])
	}

	for _, polyCoeffs := range zCoeffsBigInt {
		for _, coeff := range polyCoeffs {
			if coeff.Cmp(halfQ) > 0 {
				coeff.Sub(coeff, qBig)
			}
			coeffSquare := new(big.Int).Mul(coeff, coeff)
			sumSquares.Add(sumSquares, coeffSquare)
		}
	}

	// Internal norm bound check; intermediate values stay private. Logging
	// them at any level (even debug) creates a side-channel for validator
	// monitoring stacks that index logs.
	BsquareInt, _ := new(big.Int).SetString(Bsquare, 10)
	return sumSquares.Cmp(BsquareInt) <= 0
}

// FullRankCheck checks if the given matrix is full-rank, ignoring the first column
func FullRankCheck(D structs.Matrix[ring.Poly], r *ring.Ring) bool {
	phi := r.N()
	q := r.Modulus()
	submatrices := make([][][]*big.Int, phi)
	for i := range submatrices {
		submatrices[i] = make([][]*big.Int, len(D))
		for row := range submatrices[i] {
			submatrices[i][row] = make([]*big.Int, len(D[0])-1)
		}
	}
	for row := range D {
		for col := 1; col < len(D[row]); col++ {
			coeffs := make([]*big.Int, phi)
			r.PolyToBigint(D[row][col], 1, coeffs)
			for i := 0; i < phi; i++ {
				coeff := coeffs[i].Mod(coeffs[i], q)
				submatrices[i][row][col-1] = coeff
			}
		}
	}
	for i := range submatrices {
		if !utils.GaussianEliminationModQ(submatrices[i], q) {
			return false
		}
	}
	return true
}
