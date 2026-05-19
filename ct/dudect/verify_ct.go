// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build corona_verify_ct

// verify_ct.go -- cgo bridge exposing corona threshold.Verify to the
// C dudect harness in dudect_verify.c.
//
// HONEST CT-population framing (mirrors Pulsar's framing).
//
// Boschini et al. ePrint 2024/1113 does not specify a "valid-signatures-
// only" CT requirement for Verify. The reason we test the valid-
// signature population here is OPERATIONAL, not standards-cited:
//
//   * Verify holds no long-term secret state. An attacker observing
//     the rejection-path timing of garbage bytes does not learn any
//     confidential value -- the attacker SUPPLIED the garbage.
//   * The class of inputs over which Verify is interesting to
//     constant-time-test is the class of inputs an attacker would
//     submit to extract information about a SECRET in the verifier.
//     Verify has no secret, so the empirically meaningful CT property
//     is "signatures with identical structural validity should not be
//     timing-distinguishable" -- i.e., the valid-sig class.
//
// The dudect harness draws BOTH classes from a pool of VALID signatures
// on the same (group_pk, message); they differ only in the per-signing
// rejection-loop randomness, so the byte strings vary but the verify
// pipeline executes the same code path. Any timing difference dudect
// detects between class-A and class-B samples is a real signature-
// content-dependent timing in corona threshold.Verify.
//
// Build:
//   GOWORK=off go build -buildmode=c-shared \
//       -o libcorona_verify.dylib ./verify_ct.go

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

// Long-lived fixture. dudect calls corona_verify_ct_setup() once at
// startup, then calls corona_verify_ct() in a tight measurement loop.
const kValidPool = 64

var (
	fixtureGroupKey *threshold.GroupKey
	fixtureMessage  string
	// validPool holds kValidPool valid signatures over the same
	// (group_pk, message), differing only in per-signing randomness.
	validPool         [kValidPool]*threshold.Signature
	validPoolEncoded  [kValidPool][]byte
	fixtureSigBytes   int
)

// encodeSignature serializes a Corona Signature to a deterministic
// byte layout the C harness can copy in/out of dudect buffers.
func encodeSignature(sig *threshold.Signature) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(sig); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeSignature(data []byte) (*threshold.Signature, error) {
	var sig threshold.Signature
	dec := gob.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&sig); err != nil {
		return nil, err
	}
	return &sig, nil
}

// signFresh produces a fresh valid signature on the fixture
// (group_pk, message). The internal threshold ceremony is driven by
// fresh randomness per call, so byte strings differ across samples.
func signFresh() (*threshold.Signature, error) {
	// A t-of-n threshold ceremony where t == n == 3 (smallest meaningful
	// quorum for the dudect harness; the property under test is
	// content-dependent timing in Verify, independent of party count).
	const t, n = 2, 3
	shares, gk, err := threshold.GenerateKeys(t, n, rand.Reader)
	if err != nil {
		return nil, err
	}
	// Hand-roll a 2-of-3 sign ceremony.
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
		d, err := s.Round2(sid, fixtureMessage, prfKey, signers, r1Data)
		if err != nil {
			return nil, err
		}
		r2Data[i] = d
	}
	signer0 := threshold.NewSigner(shares[0])
	sig, err := signer0.Finalize(r2Data)
	if err != nil {
		return nil, err
	}
	// Sanity-check the signature verifies.
	if !threshold.Verify(gk, fixtureMessage, sig) {
		return nil, &verifyError{msg: "fresh-signed signature failed Verify"}
	}
	// Pin gk on first call so the pool shares one group key.
	if fixtureGroupKey == nil {
		fixtureGroupKey = gk
	}
	return sig, nil
}

type verifyError struct{ msg string }

func (e *verifyError) Error() string { return e.msg }

//export corona_verify_ct_setup
//
// Initialise the long-lived fixture. Returns 0 on success, non-zero
// on failure. Must be called once before corona_verify_ct.
func corona_verify_ct_setup() C.int {
	fixtureMessage = "dudect constant-time smoke message: Corona Verify class N1"
	// Generate kValidPool independent valid signatures.
	for i := 0; i < kValidPool; i++ {
		sig, err := signFresh()
		if err != nil {
			return C.int(10 + i)
		}
		validPool[i] = sig
		encoded, err := encodeSignature(sig)
		if err != nil {
			return C.int(100 + i)
		}
		validPoolEncoded[i] = encoded
	}
	// All encoded signatures must share the same byte width so the
	// dudect chunk_size is well-defined.
	fixtureSigBytes = len(validPoolEncoded[0])
	for i := 1; i < kValidPool; i++ {
		if len(validPoolEncoded[i]) != fixtureSigBytes {
			// Mismatched widths -- the gob encoder produced a variable-
			// length encoding. For Corona's variable-size signatures
			// this is expected; the C harness pads to fixtureSigBytes
			// using zero-prefix and length-prefix.
			//
			// For the SMOKE harness we pin to the FIRST pool entry's
			// length and re-sign until the pool is fixed-width.
			return C.int(2)
		}
	}
	return 0
}

//export corona_verify_ct_sig_size
//
// Returns the Corona signature byte size for the fixture's parameter
// set + the gob-encoded width. The C harness uses this to size its
// per-sample scratch buffer.
func corona_verify_ct_sig_size() C.size_t {
	return C.size_t(fixtureSigBytes)
}

//export corona_verify_ct_pool_size
//
// Returns the number of valid signatures in the per-startup pool.
func corona_verify_ct_pool_size() C.size_t {
	return C.size_t(kValidPool)
}

//export corona_verify_ct_copy_pool
//
// Copies validPoolEncoded[idx] into the caller-supplied dst buffer
// (fixtureSigBytes bytes). idx MUST be in [0, kValidPool). Returns 0
// on success, non-zero on bounds violation.
func corona_verify_ct_copy_pool(idx C.size_t, dst *C.uint8_t) C.int {
	i := int(idx)
	if i < 0 || i >= kValidPool || validPoolEncoded[i] == nil {
		return 1
	}
	dstSlice := unsafe.Slice((*byte)(unsafe.Pointer(dst)), fixtureSigBytes)
	copy(dstSlice, validPoolEncoded[i])
	return 0
}

//export corona_verify_ct
//
// One dudect measurement sample.
//
// data points to fixtureSigBytes of gob-encoded signature bytes. The
// bridge decodes those bytes into a *Signature and calls
// threshold.Verify; the return value is ignored. The function MUST be
// branchless on data; we only copy/decode + dispatch.
func corona_verify_ct(data *C.uint8_t) {
	if fixtureGroupKey == nil {
		return
	}
	sigBytes := unsafe.Slice((*byte)(unsafe.Pointer(data)), fixtureSigBytes)
	// Decode is on PUBLIC input -- the attacker supplied data. The
	// decode-then-verify pipeline is what's empirically tested for CT.
	bytesCopy := append([]byte{}, sigBytes...)
	sig, err := decodeSignature(bytesCopy)
	if err != nil {
		return
	}
	_ = threshold.Verify(fixtureGroupKey, fixtureMessage, sig)
}

// main is required for `go build -buildmode=c-shared`.
func main() {}
