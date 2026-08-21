// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package primitives

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/luxfi/corona/hash"
	"github.com/luxfi/corona/utils"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/sampling"
	"github.com/luxfi/lattice/v7/utils/structs"
)

const keySize = 32

// must panics if err is non-nil. Used only on call sites whose underlying
// writers are documented to never fail (bytes.Buffer.Write per its package
// contract). If it ever fires, the runtime contract has been violated by a
// dependency upgrade — surface that loudly rather than hide it. Replaces every
// previous `log.Fatalf` in this file: log.Fatal terminated the validator AND
// wrote to stdout, which leaked internal state.
func must(op string, err error) {
	if err != nil {
		panic(fmt.Sprintf("pulsar/primitives: infallible %s failed: %v", op, err))
	}
}

// PRNGKey generates a key for PRNG using the secret key share.
//
// DEPRECATED: kept only for backward-byte-compat with prior KAT runs and
// callers outside the Sign protocol. The Round-1 PRNG seed MUST mix sid
// (and ideally μ) to prevent R/E reuse across signatures of the same
// party — see PRNGKeyForRound below and LP-073 §5.8 (paper amended
// 2026-05-03 in coordination with the C++ port at luxcpp/crypto).
//
// `suite` selects the hash profile. nil resolves to the production
// default (Corona-SHA3). Output bytes differ between Corona-SHA3 and
// Corona-BLAKE3 — this is the F22 cross-profile separation.
func PRNGKey(suite hash.HashSuite, skShare structs.Vector[ring.Poly]) []byte {
	s := hash.Resolve(suite)
	buf := new(bytes.Buffer)
	_, err := skShare.WriteTo(buf)
	must("skShare.WriteTo", err)
	return s.PRF(buf.Bytes(), nil, keySize)
}

// SessionIDSize is the width in bytes of a SessionID — a 256-bit
// domain-separated identifier for one signing session.
const SessionIDSize = 32

// sessionIDTag is the nothing-up-my-sleeve domain tag for SessionID
// derivation. Version-pinned; a bump invalidates the nonce-key KATs.
var sessionIDTag = []byte("corona.sign.session-id.v1")

// DeriveSessionID maps the consensus-agreed session inputs to a 256-bit
// session identifier with no truncation. The bare int sid carries at
// most 64 bits; folding it (together with the agreed signer set T)
// through the suite TranscriptHash yields a full-width value, so an
// external collision in the low 64 bits of sid alone cannot collide the
// identifier the nonce key derives from.
//
// SessionID is the *deterministic, context-binding* half of the nonce
// key. It is NOT, on its own, sufficient to prevent nonce reuse: two
// signatures sharing (sid, T) derive the same SessionID. Reuse
// durability is provided by the fresh-salt argument to PRNGKeyForRound
// (hedged signing); see that function and SignRound1's precondition.
//
// `suite` selects the hash profile. nil resolves to the production
// default (Corona-SHA3).
func DeriveSessionID(suite hash.HashSuite, sid int, T []int) [SessionIDSize]byte {
	s := hash.Resolve(suite)
	buf := new(bytes.Buffer)
	must("binary.Write(sid)", binary.Write(buf, binary.BigEndian, int64(sid)))
	must("binary.Write(T-len)", binary.Write(buf, binary.BigEndian, int32(len(T))))
	for _, t := range T {
		must("binary.Write(T-elem)", binary.Write(buf, binary.BigEndian, int32(t)))
	}
	return s.TranscriptHash(sessionIDTag, buf.Bytes())
}

// PRNGKeyForRound generates a per-signature nonce-PRNG seed by binding
// the secret-share material to a 256-bit SessionID and a fresh 256-bit
// hedge salt.
//
// CRIT-1 (red audit) established that the Round-1 nonce seed must vary
// per signature, or R/E/D are byte-identical across every Sign call of
// the same Setup and multi-Sign leaks R via
// (z_sum − Σ s_i·λ_i·c)·u^{-1} = R. The original fix keyed on a bare
// 64-bit sid, which made reuse durability rest entirely on the external
// consensus layer never reissuing an sid for a given share. This form
// closes that residual two ways:
//
//   - sessionID is the full-width (no 64-bit truncation) deterministic
//     binding to the agreed (sid, T) — see DeriveSessionID.
//   - salt is fresh per-signature randomness drawn inside the kernel
//     (hedged signing, à la Raccoon's fresh per-signature commitment).
//     Even if sessionID collides because the consensus layer reissued
//     an sid, distinct salt makes R reuse occur with probability 2^-256.
//
// Layout: PRF(key=skShare.WriteTo bytes,
//
//	msg="CoronaNonceV3" || sessionID[32] || salt[32]).
//
// `suite` selects the hash profile. nil resolves to the production
// default (Corona-SHA3).
func PRNGKeyForRound(suite hash.HashSuite, skShare structs.Vector[ring.Poly], sessionID, salt [SessionIDSize]byte) []byte {
	s := hash.Resolve(suite)
	skBuf := new(bytes.Buffer)
	_, err := skShare.WriteTo(skBuf)
	must("skShare.WriteTo", err)
	msg := new(bytes.Buffer)
	const tag = "CoronaNonceV3"
	_, err = msg.WriteString(tag)
	must("msg.WriteString(tag)", err)
	must("msg.Write(sessionID)", binary.Write(msg, binary.BigEndian, sessionID[:]))
	must("msg.Write(salt)", binary.Write(msg, binary.BigEndian, salt[:]))
	return s.PRF(skBuf.Bytes(), msg.Bytes(), keySize)
}

// GenerateMAC generates a MAC for a given TildeD matrix and mask.
//
// `suite` selects the hash profile. nil resolves to the production
// default (Corona-SHA3).
func GenerateMAC(suite hash.HashSuite, TildeD structs.Matrix[ring.Poly], MACKey []byte, partyID int, sid int, T []int, otherParty int, verify bool) []byte {
	s := hash.Resolve(suite)
	buf := new(bytes.Buffer)

	if verify {
		must("binary.Write(otherParty)", binary.Write(buf, binary.BigEndian, int64(otherParty)))
	} else {
		must("binary.Write(partyID)", binary.Write(buf, binary.BigEndian, int64(partyID)))
	}

	_, err := TildeD.WriteTo(buf)
	must("TildeD.WriteTo", err)
	must("binary.Write(sid)", binary.Write(buf, binary.BigEndian, int64(sid)))
	must("binary.Write(T-len)", binary.Write(buf, binary.BigEndian, int32(len(T))))
	for _, t := range T {
		must("binary.Write(T-elem)", binary.Write(buf, binary.BigEndian, int32(t)))
	}

	return s.MAC(MACKey, buf.Bytes(), keySize)
}

// GaussianHash hashes parameters to a Gaussian distribution.
//
// `suite` selects the hash profile. nil resolves to the production
// default (Corona-SHA3).
func GaussianHash(suite hash.HashSuite, r *ring.Ring, hashIn []byte, mu string, sigmaU float64, boundU float64, length int) structs.Vector[ring.Poly] {
	s := hash.Resolve(suite)
	transcript := new(bytes.Buffer)
	must("binary.Write(hash)", binary.Write(transcript, binary.BigEndian, hashIn))
	_, err := transcript.WriteString(mu)
	must("transcript.WriteString(mu)", err)

	seed := s.Hu(transcript.Bytes(), keySize)
	prng, _ := sampling.NewKeyedPRNG(seed)
	gaussianParams := ring.DiscreteGaussian{Sigma: sigmaU, Bound: boundU}
	hashGaussianSampler := ring.NewGaussianSampler(prng, r, gaussianParams, false)

	return utils.SamplePolyVector(r, length, hashGaussianSampler, true, true)
}

// PRF generates pseudorandom ring elements.
//
// `suite` selects the hash profile. nil resolves to the production
// default (Corona-SHA3).
func PRF(suite hash.HashSuite, r *ring.Ring, sd_ij []byte, PRFKey []byte, mu string, hashIn []byte, n int) structs.Vector[ring.Poly] {
	s := hash.Resolve(suite)
	msg := new(bytes.Buffer)
	must("binary.Write(sd_ij)", binary.Write(msg, binary.BigEndian, sd_ij))
	must("binary.Write(hash)", binary.Write(msg, binary.BigEndian, hashIn))
	_, err := msg.WriteString(mu)
	must("msg.WriteString(mu)", err)

	seed := s.PRF(PRFKey, msg.Bytes(), keySize)
	prng, _ := sampling.NewKeyedPRNG(seed)
	PRFUniformSampler := ring.NewUniformSampler(prng, r)
	mask := utils.SamplePolyVector(r, n, PRFUniformSampler, true, true)
	return mask
}

// Hash hashes precomputable values.
//
// `suite` selects the hash profile. nil resolves to the production
// default (Corona-SHA3).
func Hash(suite hash.HashSuite, A structs.Matrix[ring.Poly], b structs.Vector[ring.Poly], D map[int]structs.Matrix[ring.Poly], sid int, T []int) []byte {
	s := hash.Resolve(suite)
	buf := new(bytes.Buffer)

	_, err := A.WriteTo(buf)
	must("A.WriteTo", err)

	_, err = b.WriteTo(buf)
	must("b.WriteTo", err)

	must("binary.Write(sid)", binary.Write(buf, binary.BigEndian, int64(sid)))
	must("binary.Write(T-len)", binary.Write(buf, binary.BigEndian, int32(len(T))))
	for _, t := range T {
		must("binary.Write(T-elem)", binary.Write(buf, binary.BigEndian, int32(t)))
	}

	// Walk D by the agreed set T, not by dense index 0..len(D)-1. D is keyed by
	// party id, so a signer set that is not {0,1,...,k-1} would otherwise read
	// absent low indices and skip the present high ones, leaving those parties
	// free to replace their round-1 commitment without moving the digest. T is
	// already written above, so its order fixes the layout.
	for _, id := range T {
		_, err = D[id].WriteTo(buf)
		must(fmt.Sprintf("D[%d].WriteTo", id), err)
	}

	out := s.TranscriptHash(buf.Bytes())
	return out[:]
}

// LowNormHash hashes to low norm ring elements.
//
// `suite` selects the hash profile. nil resolves to the production
// default (Corona-SHA3).
func LowNormHash(suite hash.HashSuite, r *ring.Ring, A structs.Matrix[ring.Poly], b structs.Vector[ring.Poly], h structs.Vector[ring.Poly], mu string, kappa int) ring.Poly {
	s := hash.Resolve(suite)
	buf := new(bytes.Buffer)

	_, err := A.WriteTo(buf)
	must("A.WriteTo", err)

	_, err = b.WriteTo(buf)
	must("b.WriteTo", err)

	_, err = h.WriteTo(buf)
	must("h.WriteTo", err)

	must("binary.Write(mu)", binary.Write(buf, binary.BigEndian, []byte(mu)))

	seed := s.Hu(buf.Bytes(), keySize)
	prng, _ := sampling.NewKeyedPRNG(seed)
	ternaryParams := ring.Ternary{H: kappa}
	ternarySampler, err := ring.NewTernarySampler(prng, r, ternaryParams, false)
	// Sampler creation is a real error path (invalid params). Surface it
	// rather than crashing the whole process via log.Fatalf.
	if err != nil {
		panic(fmt.Sprintf("pulsar/primitives: NewTernarySampler: %v", err))
	}
	c := ternarySampler.ReadNew()
	r.NTT(c, c)
	r.MForm(c, c)

	return c
}

// GenerateRandomSeed generates a random seed of length ell.
func GenerateRandomSeed() []byte {
	return utils.GetRandomBytes(keySize)
}
