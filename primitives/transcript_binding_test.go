// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package primitives

import (
	"bytes"
	"testing"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/structs"
)

func bindingRing(t *testing.T) *ring.Ring {
	t.Helper()
	r, err := ring.NewRing(256, []uint64{8380417})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// markedCommitment builds a commitment matrix carrying one distinguishing
// coefficient, so a change to it is a change to the bytes the transcript
// should cover.
func markedCommitment(r *ring.Ring, mark uint64) structs.Matrix[ring.Poly] {
	m := make(structs.Matrix[ring.Poly], 2)
	for i := range m {
		m[i] = make(structs.Vector[ring.Poly], 2)
		for j := range m[i] {
			m[i][j] = r.NewPoly()
		}
	}
	m[0][0].Coeffs[0][0] = mark
	return m
}

// TestHashBindsEveryCommitment is the binding property of the round-2
// transcript: the digest that seeds u and the per-pair masks must cover the
// round-1 commitment of every party in the agreed set.
//
// Hash walks D by dense index 0..len(D)-1 instead of by the agreed set T. For
// a signer set that is not {0, 1, ..., k-1} that walk reads absent entries and
// skips present ones, so the parties at the high indices can replace their
// commitments freely without moving the digest.
func TestHashBindsEveryCommitment(t *testing.T) {
	r := bindingRing(t)
	A := make(structs.Matrix[ring.Poly], 2)
	for i := range A {
		A[i] = structs.Vector[ring.Poly]{r.NewPoly(), r.NewPoly()}
	}
	b := structs.Vector[ring.Poly]{r.NewPoly(), r.NewPoly()}

	for _, T := range [][]int{
		{0, 1, 2},
		{2, 3, 4},
		{0, 2, 4},
		{5, 6, 7},
	} {
		t.Run("", func(t *testing.T) {
			base := map[int]structs.Matrix[ring.Poly]{}
			for i, id := range T {
				base[id] = markedCommitment(r, uint64(i+1))
			}
			baseline := Hash(nil, A, b, base, 1, T)

			for _, id := range T {
				altered := map[int]structs.Matrix[ring.Poly]{}
				for k, v := range base {
					altered[k] = v
				}
				altered[id] = markedCommitment(r, 0xDEADBEEF)

				if bytes.Equal(baseline, Hash(nil, A, b, altered, 1, T)) {
					t.Errorf("signer set %v: replacing the commitment of party %d leaves the transcript unchanged", T, id)
				}
			}
		})
	}
}

// TestHashBindsTheSessionAndTheSignerSet covers the other two transcript
// inputs. Two sessions, or two signer sets, must never share a digest — the
// digest is what a replayed partial response would have to match.
func TestHashBindsTheSessionAndTheSignerSet(t *testing.T) {
	r := bindingRing(t)
	A := structs.Matrix[ring.Poly]{{*r.NewPoly().CopyNew()}}
	b := structs.Vector[ring.Poly]{r.NewPoly()}
	D := map[int]structs.Matrix[ring.Poly]{0: markedCommitment(r, 1), 1: markedCommitment(r, 2)}

	baseline := Hash(nil, A, b, D, 1, []int{0, 1})

	if bytes.Equal(baseline, Hash(nil, A, b, D, 2, []int{0, 1})) {
		t.Error("the transcript does not bind the session id")
	}
	if bytes.Equal(baseline, Hash(nil, A, b, D, 1, []int{1, 0})) {
		t.Error("the transcript does not bind the order of the signer set")
	}
	if bytes.Equal(baseline, Hash(nil, A, b, D, 1, []int{0, 1, 2})) {
		t.Error("the transcript does not bind the size of the signer set")
	}
}

// TestHashBindsThePublicKey — the transcript names the key the round is
// signing under. Two eras that share a digest would let a partial response
// from one aggregate under the other.
func TestHashBindsThePublicKey(t *testing.T) {
	r := bindingRing(t)
	D := map[int]structs.Matrix[ring.Poly]{0: markedCommitment(r, 1)}
	T := []int{0}

	mkA := func(mark uint64) structs.Matrix[ring.Poly] {
		p := r.NewPoly()
		p.Coeffs[0][0] = mark
		return structs.Matrix[ring.Poly]{{p}}
	}
	mkB := func(mark uint64) structs.Vector[ring.Poly] {
		p := r.NewPoly()
		p.Coeffs[0][0] = mark
		return structs.Vector[ring.Poly]{p}
	}

	baseline := Hash(nil, mkA(1), mkB(1), D, 1, T)
	if bytes.Equal(baseline, Hash(nil, mkA(2), mkB(1), D, 1, T)) {
		t.Error("the transcript does not bind the public matrix A")
	}
	if bytes.Equal(baseline, Hash(nil, mkA(1), mkB(2), D, 1, T)) {
		t.Error("the transcript does not bind the rounded public key b")
	}
}

// TestDeriveSessionIDIsInjectiveOverItsInputs — the session identifier is the
// deterministic half of the nonce key. Two distinct (sid, T) that mapped to
// one identifier would put two signatures on one nonce stream whenever the
// hedge salt is pinned, which is exactly what the KAT harnesses do.
func TestDeriveSessionIDIsInjectiveOverItsInputs(t *testing.T) {
	seen := map[[SessionIDSize]byte]string{}
	record := func(label string, id [SessionIDSize]byte) {
		if prev, dup := seen[id]; dup {
			t.Errorf("%s and %s derive the same session identifier", prev, label)
		}
		seen[id] = label
	}

	for _, c := range []struct {
		label string
		sid   int
		T     []int
	}{
		{"sid=0 T={}", 0, nil},
		{"sid=0 T={0}", 0, []int{0}},
		{"sid=1 T={0}", 1, []int{0}},
		{"sid=0 T={1}", 0, []int{1}},
		{"sid=0 T={0,1}", 0, []int{0, 1}},
		{"sid=0 T={1,0}", 0, []int{1, 0}},
		{"sid=1 T={0,1}", 1, []int{0, 1}},
		{"sid=-1 T={0}", -1, []int{0}},
	} {
		record(c.label, DeriveSessionID(nil, c.sid, c.T))
	}
}

// TestGenerateMACBindsTheDirection — the tag party i sends to party j must not
// be the tag j sends to i, or a peer can reflect a tag back and pass the gate
// under the shared pairwise key.
func TestGenerateMACBindsTheDirection(t *testing.T) {
	r := bindingRing(t)
	D := markedCommitment(r, 7)
	key := bytes.Repeat([]byte{0xA5}, 32)
	T := []int{0, 1}

	iToJ := GenerateMAC(nil, D, key, 0, 1, T, 1, false)
	jVerifies := GenerateMAC(nil, D, key, 1, 1, T, 0, true)
	if !bytes.Equal(iToJ, jVerifies) {
		t.Fatal("positive control failed: the sender and the verifier disagree on the tag")
	}

	reflected := GenerateMAC(nil, D, key, 1, 1, T, 0, false)
	if bytes.Equal(iToJ, reflected) {
		t.Error("the tag i sends to j equals the tag j sends to i")
	}

	if bytes.Equal(iToJ, GenerateMAC(nil, D, key, 0, 2, T, 1, false)) {
		t.Error("the tag does not bind the session id")
	}
	if bytes.Equal(iToJ, GenerateMAC(nil, D, key, 0, 1, []int{0, 1, 2}, 1, false)) {
		t.Error("the tag does not bind the signer set")
	}
	if bytes.Equal(iToJ, GenerateMAC(nil, markedCommitment(r, 8), key, 0, 1, T, 1, false)) {
		t.Error("the tag does not bind the commitment")
	}
	if bytes.Equal(iToJ, GenerateMAC(nil, D, bytes.Repeat([]byte{0x5A}, 32), 0, 1, T, 1, false)) {
		t.Error("the tag does not bind the pairwise key")
	}
}
