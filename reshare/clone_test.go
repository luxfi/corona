// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package reshare

import (
	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/structs"
)

// cloneVector deep-copies a Share's polynomials into a fresh Vector. It is
// generic test plumbing shared by both the default-build integration tests and
// the research-tagged ones, so it lives in this untagged file.
func cloneVector(r *ring.Ring, in Share) structs.Vector[ring.Poly] {
	out := make(structs.Vector[ring.Poly], len(in))
	for i, p := range in {
		out[i] = *p.CopyNew()
	}
	_ = r // consume parameter to keep symmetry with other helpers
	return out
}
