// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package wire

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/structs"
	"github.com/luxfi/math/codec"
)

func realVector(t *testing.T, polys int) []byte {
	t.Helper()
	r, err := ring.NewRing(256, []uint64{8380417})
	if err != nil {
		t.Fatalf("ring: %v", err)
	}
	v := make(structs.Vector[ring.Poly], polys)
	for i := range v {
		v[i] = r.NewPoly()
	}
	b, err := v.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// TestFramesTheLibraryWroteAreAccepted is the control. Without it the refusals
// below would prove only that this rejects everything.
func TestFramesTheLibraryWroteAreAccepted(t *testing.T) {
	for _, polys := range []int{0, 1, 2, 5} {
		if err := ValidateVectorPolyFrame(realVector(t, polys)); err != nil {
			t.Fatalf("a frame the library wrote, %d polys, was refused: %v", polys, err)
		}
	}
}

// TestADeclaredLengthMustBeBackedByBytes. A peer writes the counts in this
// frame, and the decoder beneath allocates from them before discovering there
// is nothing to fill the space with: a fifty-byte message naming 2^40
// coefficients used to end the process with "makeslice: len out of range".
func TestADeclaredLengthMustBeBackedByBytes(t *testing.T) {
	u64 := func(n uint64) []byte {
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], n)
		return b[:]
	}
	frame := func(parts ...[]byte) []byte {
		var out []byte
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}

	for _, tc := range []struct {
		name  string
		frame []byte
	}{
		{"a vector of 2^40 polys", frame(u64(1 << 40))},
		{"a poly of 2^40 coefficients", frame(u64(1), u64(1), u64(1<<40))},
		{"2^40 levels", frame(u64(1), u64(1<<40), u64(1))},
		{"levels times coefficients would wrap", frame(u64(1), u64(1<<62), u64(4))},
		{"one more poly than there are bytes for", frame(u64(2), u64(1), u64(1), u64(0))},
		{"a count with no room for its own bytes", frame([]byte{1, 2, 3})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateVectorPolyFrame(tc.frame)
			if err == nil {
				t.Fatalf("%d bytes declaring far more were accepted", len(tc.frame))
			}
			if !errors.Is(err, codec.ErrLimitExceeded) {
				t.Fatalf("refused for the wrong reason: %v", err)
			}
		})
	}
}

// Bytes past the end of what the frame describes are bytes two different frames
// can differ in while decoding the same.
func TestTrailingBytesAreRefused(t *testing.T) {
	padded := append(realVector(t, 1), 0)
	if err := ValidateVectorPolyFrame(padded); err == nil {
		t.Fatal("a frame with a byte appended was accepted")
	}
}

// TestMatricesTheLibraryWroteAreAccepted is the control for the matrix walk: if
// the layout assumed here were wrong, this would refuse what lattigo writes.
func TestMatricesTheLibraryWroteAreAccepted(t *testing.T) {
	r, err := ring.NewRing(256, []uint64{8380417})
	if err != nil {
		t.Fatalf("ring: %v", err)
	}
	for _, dim := range [][2]int{{1, 1}, {2, 3}, {0, 0}} {
		m := make(structs.Matrix[ring.Poly], dim[0])
		for i := range m {
			m[i] = make(structs.Vector[ring.Poly], dim[1])
			for j := range m[i] {
				m[i][j] = r.NewPoly()
			}
		}
		b, err := m.MarshalBinary()
		if err != nil {
			t.Fatalf("marshal %v: %v", dim, err)
		}
		if err := ValidateMatrixPolyFrame(b); err != nil {
			t.Fatalf("a %dx%d matrix the library wrote was refused: %v", dim[0], dim[1], err)
		}
	}
}
