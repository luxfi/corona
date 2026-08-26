// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package wire is corona's wire-format hardening boundary.
//
// LP-107 Phase 4: corona consumes luxfi/math/codec for bounded
// decoding. Untrusted lattice wire data — Vector[Poly] frames from
// network peers, threshold-share blobs from disk, KAT replays —
// flows through luxfi/math/codec.Reader so the bounded-decode contract
// is centralised: no recursion, no hidden growth, no unbounded
// allocation.
//
// Before this package, corona had its own validateVectorPolyFrame
// walker in threshold/fuzz_round_test.go (test-only). This package
// replaces that with a production-grade equivalent that consumes the
// shared luxfi/math/codec substrate.
package wire

import (
	"encoding/binary"
	"fmt"

	"github.com/luxfi/math/codec"
)

// MaxLatticeUintSliceLen is corona's cap on lattigo Vector[Poly] /
// Poly inner slice lengths — matches the value warp/pulsar.go already
// enforces and the cap at threshold/fuzz_round_test.go:52.
//
// Corona canonical N = 256 and Q ≈ 2^48 (one-prime); a reasonable
// vector cap is K_max * 1 levels * 256 coeffs = bounded under the
// math/codec MaxFrameBytes.
const MaxLatticeUintSliceLen = 4096

// LatticeWireLimits is the codec.Limits configuration corona uses for
// every lattice Vector[Poly] frame on the wire.
var LatticeWireLimits = codec.Limits{
	MaxFrameBytes:     16 * 1024 * 1024,
	MaxUint16SliceLen: MaxLatticeUintSliceLen,
	MaxUint32SliceLen: MaxLatticeUintSliceLen,
	MaxUint64SliceLen: MaxLatticeUintSliceLen,
	MaxDepth:          4,
}

// ValidateVectorPolyFrame walks a lattigo Vector[Poly] frame and returns nil
// only when every length it declares is backed by bytes that are actually
// there.
//
// The frame is little-endian and self-describing:
//
//	vector := count:u64, count × poly
//	poly   := levels:u64, n:u64, levels*n × coefficient:u64
//	matrix := rows:u64, rows × vector
//
// A peer writes those counts, and the decoder beneath this sizes its
// allocations from a count before it reads the bytes meant to fill it. So a
// count is worth only the bytes behind it, and the rule at every one is the
// rule readLenPrefixed applies to the outer frame: what is declared has to fit
// in what remains. That cannot refuse an honest frame, whose bytes are all
// present, and it refuses every frame whose arithmetic does not close.
//
// MaxLatticeUintSliceLen still caps the shape corona itself will accept, above
// and beyond what the bytes could hold.
func ValidateVectorPolyFrame(frame []byte) error {
	if err := frameFits(frame); err != nil {
		return err
	}
	rest, err := walkVector(frame)
	if err != nil {
		return err
	}
	return noTrailing(rest, "vector")
}

// ValidatePolyFrame is the same walk for a single Poly, which is what a
// Signature's challenge is. A Poly carries its own level and coefficient
// counts, so it needs the same walk a vector does.
func ValidatePolyFrame(frame []byte) error {
	if err := frameFits(frame); err != nil {
		return err
	}
	rest, err := walkPoly(frame)
	if err != nil {
		return err
	}
	return noTrailing(rest, "poly")
}

// ValidateMatrixPolyFrame is the same walk for a Matrix[Poly], a count followed
// by that many vectors. A group key's A is one.
func ValidateMatrixPolyFrame(frame []byte) error {
	if err := frameFits(frame); err != nil {
		return err
	}
	rows, rest, err := takeCount(frame)
	if err != nil {
		return fmt.Errorf("matrix row count: %w", err)
	}
	for i := uint64(0); i < rows; i++ {
		if rest, err = walkVector(rest); err != nil {
			return fmt.Errorf("row %d: %w", i, err)
		}
	}
	return noTrailing(rest, "matrix")
}

func frameFits(frame []byte) error {
	if len(frame) > LatticeWireLimits.MaxFrameBytes {
		return fmt.Errorf("%w: frame is %d bytes, limit %d",
			codec.ErrLimitExceeded, len(frame), LatticeWireLimits.MaxFrameBytes)
	}
	return nil
}

// Bytes past the end of what a frame describes are bytes two frames can differ
// in while decoding the same.
func noTrailing(rest []byte, what string) error {
	if len(rest) != 0 {
		return fmt.Errorf("%w: %d trailing bytes after the %s", codec.ErrLimitExceeded, len(rest), what)
	}
	return nil
}

// takeCount reads one little-endian count and reports what follows it. A count
// is refused when the bytes left could not hold that many of anything, since
// every element costs at least one byte.
func takeCount(b []byte) (uint64, []byte, error) {
	if len(b) < 8 {
		return 0, nil, fmt.Errorf("%w: %d bytes left, a count needs 8", codec.ErrLimitExceeded, len(b))
	}
	n := binary.LittleEndian.Uint64(b[:8])
	rest := b[8:]
	if n > uint64(len(rest)) {
		return 0, nil, fmt.Errorf("%w: declared %d, only %d bytes remain", codec.ErrLimitExceeded, n, len(rest))
	}
	if n > MaxLatticeUintSliceLen {
		return 0, nil, fmt.Errorf("%w: declared %d, corona accepts at most %d",
			codec.ErrLimitExceeded, n, MaxLatticeUintSliceLen)
	}
	return n, rest, nil
}

func walkVector(b []byte) ([]byte, error) {
	count, rest, err := takeCount(b)
	if err != nil {
		return nil, fmt.Errorf("vector length: %w", err)
	}
	for i := uint64(0); i < count; i++ {
		if rest, err = walkPoly(rest); err != nil {
			return nil, fmt.Errorf("poly %d: %w", i, err)
		}
	}
	return rest, nil
}

func walkPoly(b []byte) ([]byte, error) {
	levels, rest, err := takeCount(b)
	if err != nil {
		return nil, fmt.Errorf("level count: %w", err)
	}
	n, rest, err := takeCount(rest)
	if err != nil {
		return nil, fmt.Errorf("coefficient count: %w", err)
	}
	// levels*n*8 without trusting it to fit: divide instead of multiply, so a
	// product that would wrap is refused rather than wrapping into a small
	// number that passes.
	const coeffBytes = 8
	room := uint64(len(rest)) / coeffBytes
	if n != 0 && levels > room/n {
		return nil, fmt.Errorf("%w: %d levels of %d coefficients need more than the %d bytes left",
			codec.ErrLimitExceeded, levels, n, len(rest))
	}
	return rest[levels*n*coeffBytes:], nil
}
