// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dkg2

// dkg2GPUEnabled is the runtime toggle for the goroutine fan-out path of
// the Pedersen DKG hot loop. Default off; tests opt in via
// SetDKG2GPUForTest. This is not a GPU dispatch — real GPU NTT for the
// underlying ring math lives in luxfi/lattice/v7/gpu and is reached via
// the consensus engine accel pipeline.
func init() { dkg2GPUEnabled = false }
