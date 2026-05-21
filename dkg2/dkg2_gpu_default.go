// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !gpu

package dkg2

// Off by default. Tests opt in via SetDKG2GPUForTest.
func init() {
	dkg2GPUEnabled = false
}
