// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package gpu wires Corona (R-LWE threshold signing) into the lattice
// library's per-SubRing GPU NTT dispatcher.
//
// Decomplecting note. Corona never speaks CGO directly. The lattice
// library owns ALL build-tag plumbing for the GPU path:
//
//   - cgo + gpu build: lattice/gpu.RegisterSubRing binds a SubRing to
//     a libLattice (Metal / CUDA) NTT context; subsequent r.NTT(p, p)
//     calls inside corona route through that context.
//
//   - !cgo or !gpu build: lattice/gpu.RegisterSubRing still exists
//     (mirror API) but the dispatcher returns false and the pure-Go
//     SubRing.NTT path runs. Identical bytes.
//
// Therefore this package has no build tags. UseAccelerator() flips a
// flag; corona's NewParams() constructors call RegisterRing() to bind
// each SubRing they create. On a non-GPU build the bind is a no-op
// with identical semantics.
//
// Byte-equality contract.
//
// The lattice/gpu Montgomery context is byte-equal to ring.SubRing.NTT
// by construction (gpu_montgomery_cgo.go header). Corona's
// TestDKG2_GPU_ByteEqual asserts this end-to-end through DKG2 Round 1.
// Adding GPU NTT dispatch does NOT change Pulsar threshold signature
// bytes; it only relocates the arithmetic to the GPU.
//
// Threshold gating.
//
// Single-poly Metal NTT on Apple M1 Max is slower than the pure-Go
// ring.SubRing.NTT for every measured N up to 16384
// (lattice/gpu/gpu_montgomery_cgo.go:166). The GPU dispatch win lives
// in BATCHED dispatch — many polynomials submitted in one kernel
// launch — but corona's r.NTT(poly, poly) call sites are single-poly.
// Engaging single-poly GPU dispatch at corona's production N=256
// regresses wall-clock by roughly 4x (measured: 2.5s CPU vs 10s GPU
// for BenchmarkPulsarSign_5of7 with threshold=1).
//
// Therefore UseAccelerator() picks a default threshold ABOVE corona's
// production ring degree. Operators with a batched dispatcher
// available (future luxfi/accel batch NTT plumbed through ring.NTT)
// can lower the threshold via SetThreshold; tests can set 1 to force
// every NTT through GPU for a correctness gate.
//
// The lattice-level dispatcher remains live (SubRing registered, ring
// hooks intact); RegisterRing is the prerequisite for any future
// engine-layer batch dispatch that bypasses ring.NTT and calls
// lattice/gpu.MontgomeryNTTContext.Forward(data, batch) directly with
// batch > 1 — that path IS faster on GPU even at small N.
//
// defaultThreshold = 1024 keeps corona's N=256 on the CPU path while
// leaving the dispatcher armed for any future caller working at
// N>=1024 (e.g. FHE bootstraps in thresholdvm sharing this library).
package gpu

import (
	"sync"
	"sync/atomic"

	"github.com/luxfi/lattice/v7/gpu"
	"github.com/luxfi/lattice/v7/ring"
)

// defaultThreshold is the SubRing single-poly dispatch threshold
// installed by UseAccelerator(). See the package doc above for the
// rationale: corona's N=256 sits below the M1 Max GPU break-even on
// single-poly NTT, so the default leaves single-poly dispatch off
// while keeping the SubRing registry primed for future batched paths.
const defaultThreshold uint32 = 1024

// accelEnabled is the global opt-in flag. NewParams() across corona
// consults this via Enabled() and calls RegisterRing() if set.
var accelEnabled atomic.Bool

// UseAccelerator opts every subsequent corona NewParams() into the
// lattice GPU NTT dispatch path. Idempotent. Safe to call from package
// init or from a runtime configuration step before any corona signer
// is constructed.
//
// On a !cgo or !gpu build this still flips the flag and calls into
// lattice/gpu but the dispatcher returns false and the pure-Go path
// runs — output bytes are unchanged.
func UseAccelerator() error {
	accelEnabled.Store(true)
	// See defaultThreshold doc above for the rationale: single-poly
	// GPU dispatch is slower than pure-Go at corona's production
	// N=256. The dispatcher stays armed (registered SubRings remain
	// bound) so any future batched dispatch path can engage it; the
	// threshold is conservative to keep single-poly NTT on CPU.
	gpu.SetNTTThreshold(defaultThreshold)
	return nil
}

// UseAcceleratorForce flips the opt-in flag and forces the SubRing
// threshold to 1, dispatching every NTT call on a registered SubRing
// to the GPU regardless of size. Useful for the byte-equal correctness
// tests that need to exercise the GPU path on corona's N=256 ring;
// production callers should use UseAccelerator() instead.
func UseAcceleratorForce() error {
	accelEnabled.Store(true)
	gpu.SetNTTThreshold(1)
	return nil
}

// DisableAccelerator clears the opt-in. Subsequent NewParams() calls
// will not register their SubRings. Existing registrations remain in
// place (use UnregisterRing to detach them).
func DisableAccelerator() {
	accelEnabled.Store(false)
	gpu.SetNTTThreshold(0)
}

// Enabled reports whether the opt-in flag is set. Internal corona
// callers consult this to decide whether to call RegisterRing.
func Enabled() bool { return accelEnabled.Load() }

// SetThreshold overrides the lattice/gpu single-poly dispatch
// threshold. Pass 0 to disable single-poly GPU dispatch entirely.
// See lattice/gpu.SetNTTThreshold for the full contract.
func SetThreshold(n uint32) { gpu.SetNTTThreshold(n) }

// Available reports whether the GPU NTT path is reachable on this
// build (cgo + gpu library + Metal / CUDA at runtime). The CPU
// fallback is always reachable.
func Available() bool { return gpu.Available() }

// Backend returns the active GPU backend name ("Metal", "CUDA", or a
// CPU descriptor) for diagnostic logging. Identical to the value
// returned by lattice/gpu.GetBackend(); re-exported here so corona
// callers do not import lattice/gpu directly.
func Backend() string { return gpu.GetBackend() }

// registeredMu guards registeredRings.
var (
	registeredMu    sync.Mutex
	registeredRings = map[*ring.SubRing]struct{}{}
)

// RegisterRing binds every SubRing of r into the lattice/gpu
// per-SubRing registry. Idempotent per SubRing pointer; safe to call
// multiple times with the same ring.
//
// Corona's NewParams() constructors call this for each ring they
// create (R, RXi, RNu) when Enabled() returns true. External callers
// can also register custom rings (e.g. a research harness exercising
// different parameters).
func RegisterRing(r *ring.Ring) error {
	if r == nil {
		return nil
	}
	registeredMu.Lock()
	defer registeredMu.Unlock()
	for _, s := range r.SubRings {
		if s == nil {
			continue
		}
		if _, ok := registeredRings[s]; ok {
			continue
		}
		if _, err := gpu.RegisterSubRing(s); err != nil {
			return err
		}
		registeredRings[s] = struct{}{}
	}
	return nil
}

// UnregisterRing removes the binding installed by RegisterRing. Used
// by tests to ensure subsequent benches measure the pure-Go path.
func UnregisterRing(r *ring.Ring) {
	if r == nil {
		return
	}
	registeredMu.Lock()
	defer registeredMu.Unlock()
	for _, s := range r.SubRings {
		if s == nil {
			continue
		}
		gpu.UnregisterSubRing(s)
		delete(registeredRings, s)
	}
}

// MaybeRegister is the convenience helper corona's NewParams() calls
// invoke. If Enabled() is true it binds the ring; otherwise no-op.
// Always returns the input ring so callers can chain:
//
//	r, err := ring.NewRing(N, []uint64{Q})
//	if err != nil { return err }
//	gpu.MaybeRegister(r)
func MaybeRegister(r *ring.Ring) {
	if !accelEnabled.Load() || r == nil {
		return
	}
	_ = RegisterRing(r) // best-effort; failure leaves CPU path engaged
}

// Stats describes the active accelerator state for diagnostic logging.
type Stats struct {
	Enabled         bool
	Available       bool
	Backend         string
	Threshold       uint32
	RegisteredRings int
}

// CurrentStats snapshots the accelerator state.
func CurrentStats() Stats {
	registeredMu.Lock()
	n := len(registeredRings)
	registeredMu.Unlock()
	return Stats{
		Enabled:         accelEnabled.Load(),
		Available:       gpu.Available(),
		Backend:         gpu.GetBackend(),
		Threshold:       gpu.NTTThreshold(),
		RegisteredRings: n,
	}
}
