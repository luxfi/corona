// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package gpu

import (
	"testing"

	"github.com/luxfi/lattice/v7/ring"
)

// TestUseAcceleratorIdempotent — opting in twice is harmless and leaves
// the flag set.
func TestUseAcceleratorIdempotent(t *testing.T) {
	t.Cleanup(DisableAccelerator)
	if err := UseAccelerator(); err != nil {
		t.Fatalf("UseAccelerator first call: %v", err)
	}
	if !Enabled() {
		t.Fatal("Enabled() false after first UseAccelerator")
	}
	if err := UseAccelerator(); err != nil {
		t.Fatalf("UseAccelerator second call: %v", err)
	}
	if !Enabled() {
		t.Fatal("Enabled() false after second UseAccelerator")
	}
}

// TestDisableAcceleratorClearsFlag — DisableAccelerator returns the
// global to its baseline state. Subsequent MaybeRegister calls become
// no-ops.
func TestDisableAcceleratorClearsFlag(t *testing.T) {
	t.Cleanup(DisableAccelerator)
	if err := UseAccelerator(); err != nil {
		t.Fatal(err)
	}
	DisableAccelerator()
	if Enabled() {
		t.Fatal("Enabled() true after DisableAccelerator")
	}
}

// TestRegisterRingIdempotent — calling RegisterRing twice with the same
// ring does not double-register SubRings (the lattice/gpu registry
// returns the existing context).
func TestRegisterRingIdempotent(t *testing.T) {
	t.Cleanup(func() {
		DisableAccelerator()
	})
	if err := UseAccelerator(); err != nil {
		t.Fatal(err)
	}
	r, err := ring.NewRing(256, []uint64{0x1000000004A01})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { UnregisterRing(r) })

	if err := RegisterRing(r); err != nil {
		// On non-GPU builds (no cgo backend / no Metal / no CUDA) the
		// lattice/gpu RegisterSubRing returns "GPU unavailable". The
		// rest of corona's pure-Go path is fully exercised by the other
		// suites; skip this idempotency check rather than failing.
		t.Skipf("GPU registration unavailable on this build: %v", err)
	}
	beforeStats := CurrentStats()
	if err := RegisterRing(r); err != nil {
		t.Fatalf("RegisterRing second: %v", err)
	}
	afterStats := CurrentStats()
	if beforeStats.RegisteredRings != afterStats.RegisteredRings {
		t.Fatalf("idempotency broken: %d -> %d", beforeStats.RegisteredRings, afterStats.RegisteredRings)
	}
}

// TestMaybeRegisterNoopWhenDisabled — when the accelerator is off,
// MaybeRegister leaves the SubRing registry untouched.
func TestMaybeRegisterNoopWhenDisabled(t *testing.T) {
	t.Cleanup(DisableAccelerator)
	DisableAccelerator()

	r, err := ring.NewRing(256, []uint64{0x1000000004A01})
	if err != nil {
		t.Fatal(err)
	}
	before := CurrentStats()
	MaybeRegister(r)
	after := CurrentStats()
	if before.RegisteredRings != after.RegisteredRings {
		t.Fatalf("MaybeRegister mutated registry while disabled: %d -> %d",
			before.RegisteredRings, after.RegisteredRings)
	}
}

// TestUnregisterRing — unbinding restores the pre-register state.
func TestUnregisterRing(t *testing.T) {
	t.Cleanup(DisableAccelerator)
	if err := UseAccelerator(); err != nil {
		t.Fatal(err)
	}
	r, err := ring.NewRing(256, []uint64{0x1000000004A01})
	if err != nil {
		t.Fatal(err)
	}
	before := CurrentStats()
	if err := RegisterRing(r); err != nil {
		// On non-GPU builds the lattice/gpu registry refuses
		// RegisterSubRing with "GPU unavailable". The unregister
		// semantics under that condition are vacuously preserved
		// (no binding was installed); skip rather than failing.
		t.Skipf("GPU registration unavailable on this build: %v", err)
	}
	UnregisterRing(r)
	after := CurrentStats()
	if before.RegisteredRings != after.RegisteredRings {
		t.Fatalf("registry not restored: %d -> %d", before.RegisteredRings, after.RegisteredRings)
	}
}

// TestStatsShape — sanity check that CurrentStats returns a populated
// struct. Backend string is informational; we only assert it is set
// (lattice/gpu always provides one even in the pure-Go build).
func TestStatsShape(t *testing.T) {
	s := CurrentStats()
	if s.Backend == "" {
		t.Fatal("Backend is empty")
	}
}
