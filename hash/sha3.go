// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hash

// CoronaSHA3 is the production hash suite for Corona. Built on
// cSHAKE256 / KMAC256 / TupleHash256 from FIPS 202 and NIST SP 800-185,
// vended by the shared github.com/luxfi/mlwe/transcript package — the
// single SP 800-185 surface for the Lux Module-LWE stack (Corona and
// Pulsar). Corona owns only the domain-separation tags below; the
// primitive byte encodings live in mlwe/transcript, so there is exactly
// one implementation of each construction across the stack.
//
// Customization tags pin every operation to the Corona protocol:
//
//	Hc                "CORONA-HC-v1"
//	Hu                "CORONA-HU-v1"
//	TranscriptHash    "CORONA-TRANSCRIPT-v1"
//	PRF               "CORONA-PRF-v1"     (KMAC256)
//	MAC               "CORONA-MAC-v1"     (KMAC256)
//	DerivePairwise    "CORONA-PAIRWISE-v1" (KMAC256)
//
// Distinct customization strings are essential — same primitive +
// different tag = independent oracle. Bumping any tag invalidates
// every transcript / activation cert / pairwise material in flight.
//
// All operations are stateless and goroutine-safe.

import (
	"encoding/binary"

	"github.com/luxfi/mlwe/transcript"
)

const (
	tagHC         = "CORONA-HC-v1"
	tagHU         = "CORONA-HU-v1"
	tagTranscript = "CORONA-TRANSCRIPT-v1"
	tagPRF        = "CORONA-PRF-v1"
	tagMAC        = "CORONA-MAC-v1"
	tagPairwise   = "CORONA-PAIRWISE-v1"
)

// coronaSHA3 implements HashSuite using the SP 800-185 primitives.
type coronaSHA3 struct{}

// NewCoronaSHA3 returns the production hash suite.
func NewCoronaSHA3() HashSuite { return coronaSHA3{} }

func (coronaSHA3) ID() string { return "Corona-SHA3" }

// Hc is cSHAKE256 with an empty function name and the Hc domain tag.
// (The transcript bytes are named tr here to avoid shadowing the
// imported transcript package.)
func (coronaSHA3) Hc(tr []byte) []byte {
	return transcript.CShake256("", tagHC, tr, 32)
}

func (coronaSHA3) Hu(tr []byte, outLen int) []byte {
	return transcript.CShake256("", tagHU, tr, outLen)
}

func (coronaSHA3) TranscriptHash(parts ...[]byte) [32]byte {
	out := transcript.TupleHash256(parts, 32, tagTranscript)
	var fixed [32]byte
	copy(fixed[:], out)
	return fixed
}

func (coronaSHA3) PRF(key, msg []byte, outLen int) []byte {
	return transcript.KMAC256(key, msg, outLen, tagPRF)
}

func (coronaSHA3) MAC(key, msg []byte, outLen int) []byte {
	return transcript.KMAC256(key, msg, outLen, tagMAC)
}

func (coronaSHA3) DerivePairwise(
	kex []byte,
	chainID, groupID []byte,
	eraID, generation uint64,
	i, j int,
	outLen int,
) []byte {
	a, b := i, j
	if a > b {
		a, b = b, a
	}
	var msg []byte
	msg = append(msg, transcript.EncodeString(chainID)...)
	msg = append(msg, transcript.EncodeString(groupID)...)
	var u8 [8]byte
	binary.BigEndian.PutUint64(u8[:], eraID)
	msg = append(msg, transcript.EncodeString(u8[:])...)
	binary.BigEndian.PutUint64(u8[:], generation)
	msg = append(msg, transcript.EncodeString(u8[:])...)
	var u4 [4]byte
	binary.BigEndian.PutUint32(u4[:], uint32(a))
	msg = append(msg, transcript.EncodeString(u4[:])...)
	binary.BigEndian.PutUint32(u4[:], uint32(b))
	msg = append(msg, transcript.EncodeString(u4[:])...)

	return transcript.KMAC256(kex, msg, outLen, tagPairwise)
}
