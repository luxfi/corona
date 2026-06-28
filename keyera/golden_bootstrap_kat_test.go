// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keyera

// golden_bootstrap_kat_test.go — frozen byte-stability KAT for BootstrapPedersen.
//
// These digests were captured from the dkg2-backed BootstrapPedersen at the
// Phase-3a cutover point (commit "luxfi/dkg v0.2.0 cutover gate"). They are the
// byte-stability target the vss-backed rewire MUST reproduce EXACTLY: the
// group public key bytes (bTilde), the public bootstrap transcript hash, and
// the per-validator secret-share bytes. If any of these change, the rewire has
// silently altered a deployed-cert-bearing value and the change is a BUG, not a
// re-baseline (see HANDOFF-PHASE3.md PIN 4 + the cutover gate).
//
// The rewire keeps corona's own Path-(a) noise flooding + Round_Xi finalize
// (the group-key convention) and uses luxfi/dkg only for the no-reconstruct
// share-dealing, so these digests are PRESERVED, not regenerated.

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/luxfi/corona/hash"
)

type goldenBootstrapVec struct {
	name       string
	thr, n     int
	vals       []string
	seed       string
	bTilde     string // SHA-256 of transcript.BTildeBytes
	transcript string // hex of transcript.TranscriptHash
	shares     string // SHA-256 of concatenated per-validator SkShare coeffs (LE-u64), validator order
}

// goldenBootstrapVecs were captured from the dkg2-backed path at cutover. The
// vss-backed BootstrapPedersen must reproduce them byte-for-byte.
var goldenBootstrapVecs = []goldenBootstrapVec{
	{
		name: "5/3", thr: 3, n: 5,
		vals: []string{"v1", "v2", "v3", "v4", "v5"}, seed: "golden-kat-v1",
		bTilde:     "7c0262d38cc4ce81143a404bb85c8aeb606b44302250ca86ae4f03ed535e4a69",
		transcript: "874e5b951fcc021d6af267915fdb946409c092e3cfd886f2ef0bfccb64cda51d",
		shares:     "40e6e4a16a827fba45b0ee516a97102d4c1092e0d6f5635c02e3d64c2cf37565",
	},
	{
		name: "3/2", thr: 2, n: 3,
		vals: []string{"a", "b", "c"}, seed: "golden-kat-v2",
		bTilde:     "23a376fccab01479da6ede1793b65b6fea0fa827a591aa156504c49d7986cb84",
		transcript: "28574e0d0f44c25e0168844a740d96037f055adae972982e5af398c90b430a53",
		shares:     "d231a7264d22a8adc8777e2a737372e851b5dbac9d909bfad6a02965f29870ec",
	},
}

// TestBootstrapPedersen_GoldenByteStability pins BootstrapPedersen's public
// output to frozen digests. It is the permanent proof that the vss rewire
// preserves the group key, transcript, and shares byte-for-byte.
func TestBootstrapPedersen_GoldenByteStability(t *testing.T) {
	for _, v := range goldenBootstrapVecs {
		t.Run(v.name, func(t *testing.T) {
			era, tr, err := BootstrapPedersen(
				hash.NewCoronaSHA3(), v.thr, v.vals, 0, 0, deterministicRand(v.seed),
			)
			if err != nil {
				t.Fatalf("BootstrapPedersen: %v", err)
			}

			gotBTilde := sha256.Sum256(tr.BTildeBytes)
			if got := hex.EncodeToString(gotBTilde[:]); got != v.bTilde {
				t.Fatalf("bTilde digest drift:\n want %s\n got  %s", v.bTilde, got)
			}
			if got := hex.EncodeToString(tr.TranscriptHash[:]); got != v.transcript {
				t.Fatalf("transcript hash drift:\n want %s\n got  %s", v.transcript, got)
			}

			h := sha256.New()
			for _, name := range v.vals {
				ks := era.State.Shares[name]
				if ks == nil {
					t.Fatalf("missing share for %s", name)
				}
				for _, p := range ks.SkShare {
					for _, c := range p.Coeffs[0] {
						var b [8]byte
						for i := 0; i < 8; i++ {
							b[i] = byte(c >> (8 * i))
						}
						h.Write(b[:])
					}
				}
			}
			if got := hex.EncodeToString(h.Sum(nil)); got != v.shares {
				t.Fatalf("shares digest drift:\n want %s\n got  %s", v.shares, got)
			}
		})
	}
}
