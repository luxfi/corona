// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package primitives

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/luxfi/pulsar/hash"
	"github.com/luxfi/pulsar/utils"

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
// default (Pulsar-SHA3). Output bytes differ between Pulsar-SHA3 and
// Pulsar-BLAKE3 — this is the F22 cross-profile separation.
func PRNGKey(suite hash.HashSuite, skShare structs.Vector[ring.Poly]) []byte {
	s := hash.Resolve(suite)
	buf := new(bytes.Buffer)
	_, err := skShare.WriteTo(buf)
	must("skShare.WriteTo", err)
	return s.PRF(buf.Bytes(), nil, keySize)
}

// PRNGKeyForRound generates a per-round PRNG seed by domain-separating
// the secret-share material with the session id. CRIT-1 fix
// (red audit, 2026-05-03): without sid mixing, R/E/D are byte-identical
// across every Sign call of the same Setup — multi-Sign leaks R via
// (z_sum − Σ s_i·λ_i·c)·u^{-1} = R.
//
// Layout: PRF(key=skShare.WriteTo bytes, msg="RingtailRoundV2" || be64(sid)).
// Domain tag distinguishes from any other future per-share keying.
//
// `suite` selects the hash profile. nil resolves to the production
// default (Pulsar-SHA3).
func PRNGKeyForRound(suite hash.HashSuite, skShare structs.Vector[ring.Poly], sid int64) []byte {
	s := hash.Resolve(suite)
	skBuf := new(bytes.Buffer)
	_, err := skShare.WriteTo(skBuf)
	must("skShare.WriteTo", err)
	msg := new(bytes.Buffer)
	const tag = "RingtailRoundV2"
	_, err = msg.WriteString(tag)
	must("msg.WriteString(tag)", err)
	must("binary.Write(sid)", binary.Write(msg, binary.BigEndian, sid))
	return s.PRF(skBuf.Bytes(), msg.Bytes(), keySize)
}

// GenerateMAC generates a MAC for a given TildeD matrix and mask.
//
// `suite` selects the hash profile. nil resolves to the production
// default (Pulsar-SHA3).
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
// default (Pulsar-SHA3).
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
// default (Pulsar-SHA3).
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
// default (Pulsar-SHA3).
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

	for i := 0; i < len(D); i++ {
		_, err = D[i].WriteTo(buf)
		must(fmt.Sprintf("D[%d].WriteTo", i), err)
	}

	out := s.TranscriptHash(buf.Bytes())
	return out[:]
}

// LowNormHash hashes to low norm ring elements.
//
// `suite` selects the hash profile. nil resolves to the production
// default (Pulsar-SHA3).
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
