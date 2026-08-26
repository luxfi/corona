// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package threshold

import (
	"encoding/binary"
	"testing"
)

// TestAPeerCannotEndTheProcessWithALength. Decoding a signature means reading
// counts a peer wrote, and the lattice decoder allocates from a count before it
// discovers there is nothing to fill the space with. A fifty-byte message
// naming 2^40 coefficients ended the process with "makeslice: len out of
// range" — a node killed by reading its peer's signature.
func TestAPeerCannotEndTheProcessWithALength(t *testing.T) {
	le := func(n uint64) []byte {
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], n)
		return b[:]
	}
	lenPrefixed := func(body []byte) []byte {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(body)))
		return append(l[:], body...)
	}
	// A vector naming polys, levels and coefficients, with no bytes behind them.
	claim := func(polys, levels, n uint64) []byte {
		return append(append(le(polys), le(levels)...), le(n)...)
	}
	// C is a single Poly, not a vector, so it names only levels and
	// coefficients.
	polyClaim := func(levels, n uint64) []byte {
		return append(le(levels), le(n)...)
	}
	sigFrame := func(c, z, delta []byte) []byte {
		var out []byte
		var m [4]byte
		binary.BigEndian.PutUint32(m[:], wireMagicSig)
		out = append(out, m[:]...)
		var v [2]byte
		binary.BigEndian.PutUint16(v[:], wireVersionV1)
		out = append(out, v[:]...)
		out = append(out, lenPrefixed(c)...)
		out = append(out, lenPrefixed(z)...)
		return append(out, lenPrefixed(delta)...)
	}

	honest := claim(1, 1, 0)
	for _, tc := range []struct {
		name  string
		frame []byte
	}{
		{"Z names 2^40 coefficients", sigFrame(honest, claim(1, 1, 1<<40), honest)},
		{"Delta names 2^40 coefficients", sigFrame(honest, honest, claim(1, 1, 1<<40))},
		{"Z names 2^40 polys", sigFrame(honest, claim(1<<40, 1, 1), honest)},
		{"Z names 2^40 levels", sigFrame(honest, claim(1, 1<<40, 1), honest)},
		{"C names 2^40 coefficients", sigFrame(polyClaim(1, 1<<40), honest, honest)},
		{"C names 2^40 levels", sigFrame(polyClaim(1<<40, 1), honest, honest)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%d bytes from a peer ended the process: %v", len(tc.frame), r)
				}
			}()
			var s Signature
			if err := s.UnmarshalBinary(tc.frame); err == nil {
				t.Fatal("a frame describing bytes that are not there was accepted")
			}
		})
	}
}

// A group key's A is a matrix and was decoded without ever being walked, so it
// could name rows and coefficients that were not there.
func TestAGroupKeysMatrixCannotEndTheProcess(t *testing.T) {
	le := func(n uint64) []byte {
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], n)
		return b[:]
	}
	lenPrefixed := func(body []byte) []byte {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(body)))
		return append(l[:], body...)
	}
	keyFrame := func(a, b []byte) []byte {
		var out []byte
		var m [4]byte
		binary.BigEndian.PutUint32(m[:], wireMagicGroupKey)
		out = append(out, m[:]...)
		var v [2]byte
		binary.BigEndian.PutUint16(v[:], wireVersionV1)
		out = append(out, v[:]...)
		out = append(out, lenPrefixed(a)...)
		return append(out, lenPrefixed(b)...)
	}
	honestVec := append(append(le(1), le(1)...), le(0)...)

	for _, tc := range []struct {
		name string
		a    []byte
	}{
		{"2^40 rows", le(1 << 40)},
		{"one row of 2^40 polys", append(le(1), le(1<<40)...)},
		{"one poly of 2^40 coefficients", append(append(le(1), le(1)...), append(le(1), le(1<<40)...)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("a group key from a peer ended the process: %v", r)
				}
			}()
			var gk GroupKey
			if err := gk.UnmarshalBinary(keyFrame(tc.a, honestVec)); err == nil {
				t.Fatal("a matrix describing bytes that are not there was accepted")
			}
		})
	}
}
