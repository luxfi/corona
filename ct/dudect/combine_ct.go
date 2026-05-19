// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build corona_combine_ct

// combine_ct.go -- cgo bridge exposing corona threshold Signer.Finalize
// (Combine) to the C dudect harness in dudect_combine.c.
//
// CT-population framing for Combine:
//
//   Combine has NO secret inputs in the Boschini construction:
//     - z_i shares are broadcast Round-2 messages (public on the wire).
//     - The group public key (A, bTilde) is public.
//     - The challenge c is public.
//     - The transcript_hash mu is public.
//
//   The Combine routine is trivially CT under the BGL leakage model
//   (no secret inputs => no secret-dependent leakage).
//
//   Dudect on Combine is therefore a SANITY CHECK on the Combine
//   pipeline's lack of timing artifacts as a function of which valid
//   z-share TUPLE is supplied. Class A draws a fixed valid z-tuple
//   (the dudect Welch's t-test class-A constancy requirement); class
//   B draws a uniformly-sampled valid z-tuple from the pool.

package main

/*
#cgo arm64 CFLAGS: -include ${SRCDIR}/dudect_compat.h
#include <stdint.h>
#include <stddef.h>
*/
import "C"

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"unsafe"

	"github.com/luxfi/corona/threshold"
)

const kCombinePool = 64

type combineFixture struct {
	groupKey  *threshold.GroupKey
	message   string
	signer0   *threshold.Signer
	r2Data    map[int]*threshold.Round2Data
}

var (
	combineFixtures   [kCombinePool]*combineFixture
	combinePoolBytes  [kCombinePool][]byte
	combineChunkBytes int
)

// makeCombineFixture sets up a 2-of-3 ceremony and returns a fully
// populated R2 data map ready for Finalize.
func makeCombineFixture(msg string) (*combineFixture, error) {
	const t, n = 2, 3
	shares, gk, err := threshold.GenerateKeys(t, n, rand.Reader)
	if err != nil {
		return nil, err
	}
	signers := []int{0, 1, 2}
	const sid = 1
	prfKey := make([]byte, 32)
	if _, err := rand.Read(prfKey); err != nil {
		return nil, err
	}
	r1Data := make(map[int]*threshold.Round1Data)
	for _, i := range signers {
		s := threshold.NewSigner(shares[i])
		r1Data[i] = s.Round1(sid, prfKey, signers)
	}
	r2Data := make(map[int]*threshold.Round2Data)
	for _, i := range signers {
		s := threshold.NewSigner(shares[i])
		d, err := s.Round2(sid, msg, prfKey, signers, r1Data)
		if err != nil {
			return nil, err
		}
		r2Data[i] = d
	}
	return &combineFixture{
		groupKey: gk,
		message:  msg,
		signer0:  threshold.NewSigner(shares[0]),
		r2Data:   r2Data,
	}, nil
}

// encodeCombineSample serializes the R2 data map (the variable input
// to Finalize). Sample width is the gob-encoded size.
func encodeCombineSample(f *combineFixture) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(f.r2Data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeCombineSample(data []byte) (map[int]*threshold.Round2Data, error) {
	var r2Data map[int]*threshold.Round2Data
	dec := gob.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&r2Data); err != nil {
		return nil, err
	}
	return r2Data, nil
}

//export corona_combine_ct_setup
func corona_combine_ct_setup() C.int {
	message := "dudect Combine sanity sample"
	for i := 0; i < kCombinePool; i++ {
		f, err := makeCombineFixture(message)
		if err != nil {
			return C.int(10 + i)
		}
		combineFixtures[i] = f
		encoded, err := encodeCombineSample(f)
		if err != nil {
			return C.int(100 + i)
		}
		combinePoolBytes[i] = encoded
	}
	combineChunkBytes = len(combinePoolBytes[0])
	for i := 1; i < kCombinePool; i++ {
		if len(combinePoolBytes[i]) != combineChunkBytes {
			return C.int(2)
		}
	}
	return 0
}

//export corona_combine_ct_chunk_size
func corona_combine_ct_chunk_size() C.size_t {
	return C.size_t(combineChunkBytes)
}

//export corona_combine_ct_pool_size
func corona_combine_ct_pool_size() C.size_t {
	return C.size_t(kCombinePool)
}

//export corona_combine_ct_copy_pool
func corona_combine_ct_copy_pool(idx C.size_t, dst *C.uint8_t) C.int {
	i := int(idx)
	if i < 0 || i >= kCombinePool || combinePoolBytes[i] == nil {
		return 1
	}
	dstSlice := unsafe.Slice((*byte)(unsafe.Pointer(dst)), combineChunkBytes)
	copy(dstSlice, combinePoolBytes[i])
	return 0
}

//export corona_combine_ct
//
// One dudect measurement: decode the R2 data map and run Finalize.
// Combine has no secrets, so any timing artifact dudect detects is
// an unexpected content-dependent code path in the Finalize body.
func corona_combine_ct(data *C.uint8_t) {
	if combineFixtures[0] == nil {
		return
	}
	dataSlice := unsafe.Slice((*byte)(unsafe.Pointer(data)), combineChunkBytes)
	bytesCopy := append([]byte{}, dataSlice...)
	r2Data, err := decodeCombineSample(bytesCopy)
	if err != nil {
		return
	}
	_, _ = combineFixtures[0].signer0.Finalize(r2Data)
}

func main() {}
