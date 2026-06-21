// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build corona_research

// verify_reconstruct.go isolates the master-secret reconstruction helper
// behind the `corona_research` build tag so it can NEVER be reached from a
// default production build. Reconstructing the master secret defeats the
// entire point of threshold resharing; this path exists ONLY for tests and
// KAT/oracle verification. The production reshare protocol (Reshare, Refresh
// in reshare.go) never reconstructs the secret and is built without this tag.
//
// Build/test the reconstruction path with: -tags corona_research
package reshare

import (
	"math/big"

	"github.com/luxfi/lattice/v7/ring"
)

// Verify is a research/KAT helper: it Lagrange-interpolates the input shares
// at X=0 (using the smallest-ID t-subset) and returns the reconstructed master
// secret as []ring.Poly in standard form.
//
// IMPORTANT: This recovers the master secret s, so it MUST NOT be used in
// production — only in tests and KAT verification. It is gated behind the
// `corona_research` build tag and is absent from any default build; calling it
// gives the caller the secret.
func Verify(r *ring.Ring, shares map[int]Share, t int) ([]ring.Poly, error) {
	if t > len(shares) {
		return nil, ErrTOldShortfall
	}
	q := r.Modulus()
	N := r.N()

	// Pick the smallest-ID t shares.
	quorum := selectQuorum(shares, t)
	lambda := lagrangeAtZero(quorum, q)

	var nVec int
	for _, sh := range quorum {
		nVec = len(sh)
		break
	}

	out := make([]ring.Poly, nVec)
	for p := 0; p < nVec; p++ {
		out[p] = r.NewPoly()
		for k := 0; k < N; k++ {
			acc := big.NewInt(0)
			for _, i := range sortedKeys(quorum) {
				yi := new(big.Int).SetUint64(quorum[i][p].Coeffs[0][k])
				term := new(big.Int).Mul(lambda[i], yi)
				acc.Add(acc, term)
			}
			acc.Mod(acc, q)
			out[p].Coeffs[0][k] = acc.Uint64()
		}
	}
	return out, nil
}
