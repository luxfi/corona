// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package threshold

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/luxfi/corona/wire"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/structs"
)

// Wire-format identifiers. Domain-separated so a Signature cannot be
// confused with a GroupKey on the wire and so two profile versions
// cannot alias.
const (
	wireMagicSig      uint32 = 0x434F5253 // "CORS" Corona Signature
	wireMagicGroupKey uint32 = 0x434F5247 // "CORG" Corona GroupKey
	wireVersionV1     uint16 = 1
)

// Errors returned by the wire codec.
var (
	ErrWireMagicMismatch   = errors.New("corona/wire: magic mismatch")
	ErrWireVersionMismatch = errors.New("corona/wire: version mismatch")
	ErrWireFrameTooShort   = errors.New("corona/wire: frame too short")
	ErrWireFrameRejected   = errors.New("corona/wire: frame rejected by bounded reader")
)

// MarshalBinary serializes a Signature into a canonical wire form.
//
// Layout (big-endian):
//
//	magic(4) || version(2) || len(C)(4) || C || len(Z)(4) || Z || len(Delta)(4) || Delta
//
// Each polynomial / vector is encoded via the underlying lattigo
// MarshalBinary so corona owns only framing and version bytes.
func (s *Signature) MarshalBinary() ([]byte, error) {
	if s == nil {
		return nil, errors.New("corona: nil Signature")
	}

	cBytes, err := s.C.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("corona/wire: C.MarshalBinary: %w", err)
	}
	zBytes, err := s.Z.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("corona/wire: Z.MarshalBinary: %w", err)
	}
	dBytes, err := s.Delta.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("corona/wire: Delta.MarshalBinary: %w", err)
	}

	out := make([]byte, 0, 4+2+4+len(cBytes)+4+len(zBytes)+4+len(dBytes))
	out = binary.BigEndian.AppendUint32(out, wireMagicSig)
	out = binary.BigEndian.AppendUint16(out, wireVersionV1)
	out = binary.BigEndian.AppendUint32(out, uint32(len(cBytes)))
	out = append(out, cBytes...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(zBytes)))
	out = append(out, zBytes...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(dBytes)))
	out = append(out, dBytes...)
	return out, nil
}

// UnmarshalBinary parses a Signature from canonical wire form.
//
// Validation order is strict — magic + version are checked before any
// allocation, then each inner frame is bounded-decoded via
// wire.ValidateVectorPolyFrame.
//
// The Signature.C, .Z, .Delta polynomials are re-initialised on a fresh
// ring derived from the active sign.Q / sign.LogN parameters at parse
// time (matches NewParams()). Callers MUST verify that the parsed
// Signature is consistent with the GroupKey they intend to verify
// against — the wire format does not carry ring parameters.
func (s *Signature) UnmarshalBinary(b []byte) error {
	if s == nil {
		return errors.New("corona: nil Signature receiver")
	}
	if len(b) < 4+2+4*3 {
		return ErrWireFrameTooShort
	}
	r := bytes.NewReader(b)

	var magic uint32
	if err := binary.Read(r, binary.BigEndian, &magic); err != nil {
		return fmt.Errorf("corona/wire: read magic: %w", err)
	}
	if magic != wireMagicSig {
		return fmt.Errorf("%w: got 0x%08x, want 0x%08x", ErrWireMagicMismatch, magic, wireMagicSig)
	}

	var version uint16
	if err := binary.Read(r, binary.BigEndian, &version); err != nil {
		return fmt.Errorf("corona/wire: read version: %w", err)
	}
	if version != wireVersionV1 {
		return fmt.Errorf("%w: got %d, want %d", ErrWireVersionMismatch, version, wireVersionV1)
	}

	cBytes, err := readLenPrefixed(r)
	if err != nil {
		return fmt.Errorf("corona/wire: read C: %w", err)
	}
	zBytes, err := readLenPrefixed(r)
	if err != nil {
		return fmt.Errorf("corona/wire: read Z: %w", err)
	}
	dBytes, err := readLenPrefixed(r)
	if err != nil {
		return fmt.Errorf("corona/wire: read Delta: %w", err)
	}
	if r.Len() != 0 {
		return fmt.Errorf("corona/wire: %d trailing bytes after Signature", r.Len())
	}

	// Bounded validation of Z, Delta vector frames (C is a single Poly
	// which is bounded by the ring size already).
	if err := wire.ValidateVectorPolyFrame(zBytes); err != nil {
		return fmt.Errorf("%w: Z: %v", ErrWireFrameRejected, err)
	}
	if err := wire.ValidateVectorPolyFrame(dBytes); err != nil {
		return fmt.Errorf("%w: Delta: %v", ErrWireFrameRejected, err)
	}

	var c ring.Poly
	if err := c.UnmarshalBinary(cBytes); err != nil {
		return fmt.Errorf("corona/wire: C.UnmarshalBinary: %w", err)
	}
	var z structs.Vector[ring.Poly]
	if err := z.UnmarshalBinary(zBytes); err != nil {
		return fmt.Errorf("corona/wire: Z.UnmarshalBinary: %w", err)
	}
	var delta structs.Vector[ring.Poly]
	if err := delta.UnmarshalBinary(dBytes); err != nil {
		return fmt.Errorf("corona/wire: Delta.UnmarshalBinary: %w", err)
	}

	s.C = c
	s.Z = z
	s.Delta = delta
	return nil
}

// MarshalBinary serializes the public GroupKey to a canonical wire
// form. Only the public matrix A and rounded public key BTilde are
// emitted; Params is reconstructed on the verifier side from a fresh
// NewParams() call (matches the GenerateKeys / Bootstrap conventions).
//
// Layout:
//
//	magic(4) || version(2) || len(A)(4) || A || len(BTilde)(4) || BTilde
func (gk *GroupKey) MarshalBinary() ([]byte, error) {
	if gk == nil {
		return nil, errors.New("corona: nil GroupKey")
	}
	aBytes, err := gk.A.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("corona/wire: A.MarshalBinary: %w", err)
	}
	bBytes, err := gk.BTilde.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("corona/wire: BTilde.MarshalBinary: %w", err)
	}
	out := make([]byte, 0, 4+2+4+len(aBytes)+4+len(bBytes))
	out = binary.BigEndian.AppendUint32(out, wireMagicGroupKey)
	out = binary.BigEndian.AppendUint16(out, wireVersionV1)
	out = binary.BigEndian.AppendUint32(out, uint32(len(aBytes)))
	out = append(out, aBytes...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(bBytes)))
	out = append(out, bBytes...)
	return out, nil
}

// UnmarshalBinary parses a GroupKey from canonical wire form.
//
// Params is re-initialised on this side via NewParams(); the receiver's
// A and BTilde are bound to that fresh ring. Callers MUST NOT assume
// the parsed Params is pointer-equal to any other GroupKey's Params.
func (gk *GroupKey) UnmarshalBinary(b []byte) error {
	if gk == nil {
		return errors.New("corona: nil GroupKey receiver")
	}
	if len(b) < 4+2+4*2 {
		return ErrWireFrameTooShort
	}
	r := bytes.NewReader(b)

	var magic uint32
	if err := binary.Read(r, binary.BigEndian, &magic); err != nil {
		return fmt.Errorf("corona/wire: read magic: %w", err)
	}
	if magic != wireMagicGroupKey {
		return fmt.Errorf("%w: got 0x%08x, want 0x%08x", ErrWireMagicMismatch, magic, wireMagicGroupKey)
	}

	var version uint16
	if err := binary.Read(r, binary.BigEndian, &version); err != nil {
		return fmt.Errorf("corona/wire: read version: %w", err)
	}
	if version != wireVersionV1 {
		return fmt.Errorf("%w: got %d, want %d", ErrWireVersionMismatch, version, wireVersionV1)
	}

	aBytes, err := readLenPrefixed(r)
	if err != nil {
		return fmt.Errorf("corona/wire: read A: %w", err)
	}
	bBytes, err := readLenPrefixed(r)
	if err != nil {
		return fmt.Errorf("corona/wire: read BTilde: %w", err)
	}
	if r.Len() != 0 {
		return fmt.Errorf("corona/wire: %d trailing bytes after GroupKey", r.Len())
	}

	if err := wire.ValidateVectorPolyFrame(bBytes); err != nil {
		return fmt.Errorf("%w: BTilde: %v", ErrWireFrameRejected, err)
	}

	var a structs.Matrix[ring.Poly]
	if err := a.UnmarshalBinary(aBytes); err != nil {
		return fmt.Errorf("corona/wire: A.UnmarshalBinary: %w", err)
	}
	var bTilde structs.Vector[ring.Poly]
	if err := bTilde.UnmarshalBinary(bBytes); err != nil {
		return fmt.Errorf("corona/wire: BTilde.UnmarshalBinary: %w", err)
	}

	params, err := NewParams()
	if err != nil {
		return fmt.Errorf("corona/wire: rebuild Params: %w", err)
	}

	gk.A = a
	gk.BTilde = bTilde
	gk.Params = params
	return nil
}

// VerifyBytes is the stateless verifier the threshold orchestration
// layer (luxfi/threshold/pkg/thresholdd) needs to publish a signature
// over a JSON-RPC bus: it accepts the canonical wire bytes of a
// GroupKey and a Signature and returns true iff the signature verifies
// under the group key for the supplied message.
//
// Rejection of any malformed input returns false (NOT an error) — the
// dispatcher distinguishes "no valid signature" from "infrastructure
// error" via the JSON-RPC envelope; bytes-in, bool-out keeps this
// helper pure.
func VerifyBytes(gkBytes []byte, message string, sigBytes []byte) bool {
	var gk GroupKey
	if err := gk.UnmarshalBinary(gkBytes); err != nil {
		return false
	}
	var sig Signature
	if err := sig.UnmarshalBinary(sigBytes); err != nil {
		return false
	}
	return Verify(&gk, message, &sig)
}

// readLenPrefixed reads a uint32 big-endian length followed by that
// many bytes from r. The length is bounded by r.Len() so a malformed
// header cannot trigger an oversized allocation.
func readLenPrefixed(r *bytes.Reader) ([]byte, error) {
	var l uint32
	if err := binary.Read(r, binary.BigEndian, &l); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}
	if int(l) > r.Len() {
		return nil, fmt.Errorf("declared length %d exceeds remaining %d", l, r.Len())
	}
	buf := make([]byte, l)
	if _, err := r.Read(buf); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return buf, nil
}
