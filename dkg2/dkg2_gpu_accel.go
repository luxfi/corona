// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build gpu

package dkg2

// On by default in the gpu build. The fan-out is pure Go (no CGO); the
// luxfi/accel kernel slots in at the engine layer for the v0.6+
// submission pipeline.
func init() {
	dkg2GPUEnabled = true
}
