// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package threshold

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

// TestSignatureRoundtrip generates a real threshold signature, marshals
// it, unmarshals it, and verifies the parsed signature against the
// parsed group key over the same message. Byte-equal serialization is
// enforced.
//
// NOTE: cannot t.Parallel — GenerateKeys mutates sign.K / sign.Threshold
// package globals (see threshold.go:123-124). The wire codec itself is
// pure; this is a kernel-side limitation we accept rather than refactor
// out from under sibling agents who own pulsar/.
func TestSignatureWireRoundtrip(t *testing.T) {
	const tThr, n = 1, 2
	shares, gk, err := GenerateKeys(tThr, n, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}

	// Two-party signing (smallest committee that exercises the protocol).
	signers := []int{0, 1}
	prfKey := make([]byte, 32)
	if _, err := rand.Read(prfKey); err != nil {
		t.Fatalf("rand.Read prfKey: %v", err)
	}

	sigA := NewSigner(shares[0])
	sigB := NewSigner(shares[1])

	const sessionID = 42
	r1A := sigA.Round1(sessionID, prfKey, signers)
	r1B := sigB.Round1(sessionID, prfKey, signers)
	r1Data := map[int]*Round1Data{0: r1A, 1: r1B}

	msg := "corona-wire-roundtrip-test"
	r2A, err := sigA.Round2(sessionID, msg, prfKey, signers, r1Data)
	if err != nil {
		t.Fatalf("Round2 A: %v", err)
	}
	r2B, err := sigB.Round2(sessionID, msg, prfKey, signers, r1Data)
	if err != nil {
		t.Fatalf("Round2 B: %v", err)
	}
	r2Data := map[int]*Round2Data{0: r2A, 1: r2B}

	sig, err := sigA.Finalize(r2Data)
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}

	if !Verify(gk, msg, sig) {
		t.Fatal("baseline Verify failed before serialization")
	}

	// MarshalBinary + UnmarshalBinary roundtrip for Signature.
	sigBytes, err := sig.MarshalBinary()
	if err != nil {
		t.Fatalf("sig.MarshalBinary: %v", err)
	}
	var sigParsed Signature
	if err := sigParsed.UnmarshalBinary(sigBytes); err != nil {
		t.Fatalf("sig.UnmarshalBinary: %v", err)
	}

	// Second marshal must be byte-identical to the first.
	sigBytes2, err := sigParsed.MarshalBinary()
	if err != nil {
		t.Fatalf("sigParsed.MarshalBinary: %v", err)
	}
	if !bytes.Equal(sigBytes, sigBytes2) {
		t.Fatalf("Signature re-marshal not byte-equal: first %d bytes, second %d bytes", len(sigBytes), len(sigBytes2))
	}

	// MarshalBinary + UnmarshalBinary roundtrip for GroupKey.
	gkBytes, err := gk.MarshalBinary()
	if err != nil {
		t.Fatalf("gk.MarshalBinary: %v", err)
	}
	var gkParsed GroupKey
	if err := gkParsed.UnmarshalBinary(gkBytes); err != nil {
		t.Fatalf("gk.UnmarshalBinary: %v", err)
	}

	gkBytes2, err := gkParsed.MarshalBinary()
	if err != nil {
		t.Fatalf("gkParsed.MarshalBinary: %v", err)
	}
	if !bytes.Equal(gkBytes, gkBytes2) {
		t.Fatalf("GroupKey re-marshal not byte-equal: first %d, second %d", len(gkBytes), len(gkBytes2))
	}

	// Stateless VerifyBytes path — the surface threshold/pkg/thresholdd
	// uses.
	if !VerifyBytes(gkBytes, msg, sigBytes) {
		t.Fatal("VerifyBytes returned false on a valid signature")
	}

	// Negative: corrupted signature MUST not verify.
	corrupted := append([]byte(nil), sigBytes...)
	corrupted[len(corrupted)-1] ^= 0x01
	if VerifyBytes(gkBytes, msg, corrupted) {
		t.Fatal("VerifyBytes returned true on a corrupted signature")
	}

	// Negative: wrong message MUST not verify.
	if VerifyBytes(gkBytes, msg+"-tampered", sigBytes) {
		t.Fatal("VerifyBytes returned true on a tampered message")
	}
}

// TestSignatureWireRejectMalformed ensures the wire codec rejects
// short, magic-mismatched, and version-mismatched frames before any
// allocation.
func TestSignatureWireRejectMalformed(t *testing.T) {
	cases := []struct {
		name string
		buf  []byte
		want error
	}{
		{"empty", []byte{}, ErrWireFrameTooShort},
		{"too-short", make([]byte, 4), ErrWireFrameTooShort},
		{
			"wrong-magic",
			func() []byte {
				b := make([]byte, 4+2+4*3)
				// magic bytes != wireMagicSig
				b[0] = 0xff
				b[1] = 0xff
				b[2] = 0xff
				b[3] = 0xff
				// version=1
				b[5] = 0x01
				return b
			}(),
			ErrWireMagicMismatch,
		},
		{
			"wrong-version",
			func() []byte {
				b := make([]byte, 4+2+4*3)
				// correct magic 0x434F5253
				b[0] = 0x43
				b[1] = 0x4F
				b[2] = 0x52
				b[3] = 0x53
				// version=999
				b[4] = 0x03
				b[5] = 0xe7
				return b
			}(),
			ErrWireVersionMismatch,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var sig Signature
			err := sig.UnmarshalBinary(tc.buf)
			if err == nil {
				t.Fatalf("expected error %v, got nil", tc.want)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
		})
	}
}

// TestGroupKeyWireRejectMalformed mirrors the Signature rejection
// suite for GroupKey.
func TestGroupKeyWireRejectMalformed(t *testing.T) {
	cases := []struct {
		name string
		buf  []byte
		want error
	}{
		{"empty", []byte{}, ErrWireFrameTooShort},
		{
			"sig-magic-into-groupkey",
			func() []byte {
				// Signature magic but feed into GroupKey parser — must
				// be rejected as mismatch, not accepted as anything.
				b := make([]byte, 4+2+4*2)
				b[0] = 0x43
				b[1] = 0x4F
				b[2] = 0x52
				b[3] = 0x53
				b[5] = 0x01
				return b
			}(),
			ErrWireMagicMismatch,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gk GroupKey
			err := gk.UnmarshalBinary(tc.buf)
			if err == nil {
				t.Fatalf("expected error %v, got nil", tc.want)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
		})
	}
}

// TestVerifyBytesRejectsCrossWire ensures VerifyBytes rejects a
// GroupKey-magic frame in the Signature slot and vice versa — domain
// separation must be effective.
func TestVerifyBytesRejectsCrossWire(t *testing.T) {
	shares, gk, err := GenerateKeys(1, 2, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	_ = shares
	gkBytes, err := gk.MarshalBinary()
	if err != nil {
		t.Fatalf("gk.MarshalBinary: %v", err)
	}
	// Feed gkBytes in the signature slot — VerifyBytes must reject.
	if VerifyBytes(gkBytes, "msg", gkBytes) {
		t.Fatal("VerifyBytes accepted GroupKey magic in signature slot")
	}
	// Feed empty bytes — also reject.
	if VerifyBytes(gkBytes, "msg", nil) {
		t.Fatal("VerifyBytes accepted nil signature")
	}
	if VerifyBytes(nil, "msg", gkBytes) {
		t.Fatal("VerifyBytes accepted nil group key")
	}
}
