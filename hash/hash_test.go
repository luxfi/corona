// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hash

import (
	"bytes"
	"testing"
)

// TestSuiteIDs ensures the two suites declare distinct, stable IDs.
func TestSuiteIDs(t *testing.T) {
	sha3 := NewCoronaSHA3()
	bl3 := NewCoronaBLAKE3()

	if sha3.ID() != "Corona-SHA3" {
		t.Errorf("SHA3 suite ID: want Corona-SHA3, got %q", sha3.ID())
	}
	if bl3.ID() != "Corona-BLAKE3" {
		t.Errorf("BLAKE3 suite ID: want Corona-BLAKE3, got %q", bl3.ID())
	}
	if sha3.ID() == bl3.ID() {
		t.Error("SHA3 and BLAKE3 suites must declare distinct IDs")
	}
	if Default().ID() != DefaultID {
		t.Errorf("Default ID: want %q got %q", DefaultID, Default().ID())
	}
}

// TestDefaultIsSHA3 — production default must be SHA3.
func TestDefaultIsSHA3(t *testing.T) {
	if Default().ID() != "Corona-SHA3" {
		t.Fatalf("production default must be SHA3; got %q", Default().ID())
	}
}

// TestResolveNil — nil resolves to default.
func TestResolveNil(t *testing.T) {
	if Resolve(nil).ID() != DefaultID {
		t.Errorf("Resolve(nil) must return the production default")
	}
	bl3 := NewCoronaBLAKE3()
	if Resolve(bl3).ID() != bl3.ID() {
		t.Errorf("Resolve(suite) must return that suite")
	}
}

// TestSuitesProduceDifferentBytes — two suites with distinct IDs must
// produce distinct bytes for the same input.
func TestSuitesProduceDifferentBytes(t *testing.T) {
	sha3 := NewCoronaSHA3()
	bl3 := NewCoronaBLAKE3()

	t1 := sha3.TranscriptHash([]byte("a"), []byte("b"))
	t2 := bl3.TranscriptHash([]byte("a"), []byte("b"))
	if t1 == t2 {
		t.Errorf("TranscriptHash collision across SHA3/BLAKE3 — wrong domain separation")
	}

	if bytes.Equal(sha3.Hc([]byte("x")), bl3.Hc([]byte("x"))) {
		t.Errorf("Hc collision across SHA3/BLAKE3")
	}
	if bytes.Equal(sha3.Hu([]byte("x"), 32), bl3.Hu([]byte("x"), 32)) {
		t.Errorf("Hu collision across SHA3/BLAKE3")
	}
	if bytes.Equal(sha3.PRF([]byte("k"), []byte("m"), 32), bl3.PRF([]byte("k"), []byte("m"), 32)) {
		t.Errorf("PRF collision across SHA3/BLAKE3")
	}
	if bytes.Equal(sha3.MAC([]byte("k"), []byte("m"), 32), bl3.MAC([]byte("k"), []byte("m"), 32)) {
		t.Errorf("MAC collision across SHA3/BLAKE3")
	}
}

// TestPRFAndMACDifferByCustomization — same suite, same key, same
// message, but PRF and MAC must produce distinct bytes.
func TestPRFAndMACDifferByCustomization(t *testing.T) {
	for _, s := range []HashSuite{NewCoronaSHA3(), NewCoronaBLAKE3()} {
		key := []byte("00000000000000000000000000000000") // 32 bytes
		msg := []byte("same-message")
		prf := s.PRF(key, msg, 32)
		mac := s.MAC(key, msg, 32)
		if bytes.Equal(prf, mac) {
			t.Errorf("%s: PRF and MAC must differ by customization tag", s.ID())
		}
	}
}

// TestHcAndHuDifferByCustomization — same suite, same input, different
// tags → different bytes.
func TestHcAndHuDifferByCustomization(t *testing.T) {
	for _, s := range []HashSuite{NewCoronaSHA3(), NewCoronaBLAKE3()} {
		hc := s.Hc([]byte("transcript"))
		hu := s.Hu([]byte("transcript"), 32)
		if bytes.Equal(hc, hu) {
			t.Errorf("%s: Hc and Hu must differ by tag", s.ID())
		}
	}
}

// TestTranscriptHashAvoidsConcatenationCollisions — TupleHash framing
// must reject two distinct lists whose naive concatenation is identical.
func TestTranscriptHashAvoidsConcatenationCollisions(t *testing.T) {
	for _, s := range []HashSuite{NewCoronaSHA3(), NewCoronaBLAKE3()} {
		a := s.TranscriptHash([]byte("abc"), []byte(""))
		b := s.TranscriptHash([]byte("a"), []byte("bc"))
		if a == b {
			t.Errorf("%s: TranscriptHash collided on different field splits — framing broken", s.ID())
		}
		c := s.TranscriptHash([]byte("ab"), []byte("c"))
		if a == c || b == c {
			t.Errorf("%s: TranscriptHash collided on different field splits", s.ID())
		}
	}
}

// TestPairwiseCanonicalOrdering — DerivePairwise must produce the same
// bytes for (i, j) and (j, i).
func TestPairwiseCanonicalOrdering(t *testing.T) {
	for _, s := range []HashSuite{NewCoronaSHA3(), NewCoronaBLAKE3()} {
		kex := []byte("0123456789abcdef0123456789abcdef")
		ab := s.DerivePairwise(kex, []byte("chain"), []byte("group"), 7, 3, 2, 5, 32)
		ba := s.DerivePairwise(kex, []byte("chain"), []byte("group"), 7, 3, 5, 2, 32)
		if !bytes.Equal(ab, ba) {
			t.Errorf("%s: DerivePairwise must be symmetric in (i, j)", s.ID())
		}
	}
}

// TestPairwiseDistinctEras — different (era, generation) MUST yield
// different pairwise material.
func TestPairwiseDistinctEras(t *testing.T) {
	for _, s := range []HashSuite{NewCoronaSHA3(), NewCoronaBLAKE3()} {
		kex := []byte("0123456789abcdef0123456789abcdef")
		base := s.DerivePairwise(kex, []byte("chain"), []byte("group"), 7, 3, 2, 5, 32)
		era2 := s.DerivePairwise(kex, []byte("chain"), []byte("group"), 8, 3, 2, 5, 32)
		gen2 := s.DerivePairwise(kex, []byte("chain"), []byte("group"), 7, 4, 2, 5, 32)
		ch2 := s.DerivePairwise(kex, []byte("CHAIN"), []byte("group"), 7, 3, 2, 5, 32)
		if bytes.Equal(base, era2) {
			t.Errorf("%s: era change did not affect pairwise output", s.ID())
		}
		if bytes.Equal(base, gen2) {
			t.Errorf("%s: generation change did not affect pairwise output", s.ID())
		}
		if bytes.Equal(base, ch2) {
			t.Errorf("%s: chain_id change did not affect pairwise output", s.ID())
		}
	}
}

// NIST SP 800-185 primitive vectors (left/right_encode, KMAC256,
// TupleHash256) are owned and tested by github.com/luxfi/mlwe/transcript
// (transcript_test.go: cSHAKE256 NIST Sample #3, the §2.3 encoders, and
// the KMAC/TupleHash spec-construction KATs). Corona no longer carries a
// parallel copy of those primitive tests — it tests only its own suite
// composition (tags, domain separation, determinism) below.

// TestSuiteDeterminism — same input, two calls, identical bytes.
func TestSuiteDeterminism(t *testing.T) {
	for _, s := range []HashSuite{NewCoronaSHA3(), NewCoronaBLAKE3()} {
		a := s.TranscriptHash([]byte("a"), []byte("b"))
		b := s.TranscriptHash([]byte("a"), []byte("b"))
		if a != b {
			t.Errorf("%s: TranscriptHash not deterministic", s.ID())
		}
		if !bytes.Equal(s.Hc([]byte("x")), s.Hc([]byte("x"))) {
			t.Errorf("%s: Hc not deterministic", s.ID())
		}
		if !bytes.Equal(s.Hu([]byte("x"), 32), s.Hu([]byte("x"), 32)) {
			t.Errorf("%s: Hu not deterministic", s.ID())
		}
	}
}
