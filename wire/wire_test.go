// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/luxfi/math/codec"
)

// vectorFrame writes the frame lattigo writes: a little-endian count followed
// by that many polys, each a level count, a coefficient count, and the
// coefficients themselves. Tests build frames this way so that what they accept
// is what a peer can actually send.
func vectorFrame(polys, levels, n uint64) []byte {
	var buf bytes.Buffer
	le := func(v uint64) { _ = binary.Write(&buf, binary.LittleEndian, v) }
	le(polys)
	for i := uint64(0); i < polys; i++ {
		le(levels)
		le(n)
		buf.Write(make([]byte, levels*n*8))
	}
	return buf.Bytes()
}

// TestValidateVectorPolyFrame_RejectsHugeLength is the regression test for
// lattice issue #4 (Vector[T].ReadFrom unbounded allocation): a short frame
// naming an enormous count must be refused rather than allocated from.
func TestValidateVectorPolyFrame_RejectsHugeLength(t *testing.T) {
	// The value from the original fuzz finding.
	const huge = uint64(70_368_955_777_453)

	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, huge)

	err := ValidateVectorPolyFrame(buf.Bytes())
	if err == nil {
		t.Fatal("a frame declaring 70 trillion polys was accepted")
	}
	if !errors.Is(err, codec.ErrLimitExceeded) {
		t.Errorf("err is not ErrLimitExceeded: %v", err)
	}
}

// TestValidateVectorPolyFrame_HappyPath accepts a frame whose counts are all
// backed by bytes that are there.
func TestValidateVectorPolyFrame_HappyPath(t *testing.T) {
	if err := ValidateVectorPolyFrame(vectorFrame(3, 1, 16)); err != nil {
		t.Errorf("happy-path: %v", err)
	}
}

// TestValidateVectorPolyFrame_AtCap accepts exactly MaxLatticeUintSliceLen
// coefficients, which is the largest shape corona will read.
func TestValidateVectorPolyFrame_AtCap(t *testing.T) {
	if err := ValidateVectorPolyFrame(vectorFrame(1, 1, MaxLatticeUintSliceLen)); err != nil {
		t.Errorf("at-cap: %v", err)
	}
}

// TestValidateVectorPolyFrame_OverCap rejects MaxLatticeUintSliceLen + 1 even
// when the bytes to back it are present, because that is a shape corona does
// not read whatever the sender is willing to send.
func TestValidateVectorPolyFrame_OverCap(t *testing.T) {
	err := ValidateVectorPolyFrame(vectorFrame(1, 1, MaxLatticeUintSliceLen+1))
	if err == nil {
		t.Fatal("over-cap returned nil")
	}
	if !errors.Is(err, codec.ErrLimitExceeded) {
		t.Errorf("err is not ErrLimitExceeded: %v", err)
	}
}
