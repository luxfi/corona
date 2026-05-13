// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hash

// CoronaSHA3 is the production hash suite for Corona. Built on
// cSHAKE256 / KMAC256 / TupleHash256 from FIPS 202 and NIST SP 800-185.
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

func (coronaSHA3) Hc(transcript []byte) []byte {
	return cshake256Stream(tagHC, transcript, 32)
}

func (coronaSHA3) Hu(transcript []byte, outLen int) []byte {
	return cshake256Stream(tagHU, transcript, outLen)
}

func (coronaSHA3) TranscriptHash(parts ...[]byte) [32]byte {
	out := tupleHash256(parts, 32, tagTranscript)
	var fixed [32]byte
	copy(fixed[:], out)
	return fixed
}

func (coronaSHA3) PRF(key, msg []byte, outLen int) []byte {
	return kmac256(key, msg, outLen, tagPRF)
}

func (coronaSHA3) MAC(key, msg []byte, outLen int) []byte {
	return kmac256(key, msg, outLen, tagMAC)
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
	msg = append(msg, encodeString(chainID)...)
	msg = append(msg, encodeString(groupID)...)
	var u8 [8]byte
	binary.BigEndian.PutUint64(u8[:], eraID)
	msg = append(msg, encodeString(u8[:])...)
	binary.BigEndian.PutUint64(u8[:], generation)
	msg = append(msg, encodeString(u8[:])...)
	var u4 [4]byte
	binary.BigEndian.PutUint32(u4[:], uint32(a))
	msg = append(msg, encodeString(u4[:])...)
	binary.BigEndian.PutUint32(u4[:], uint32(b))
	msg = append(msg, encodeString(u4[:])...)

	return kmac256(kex, msg, outLen, tagPairwise)
}
