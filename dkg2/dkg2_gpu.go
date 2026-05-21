// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dkg2

// dkg2_gpu.go — GPU-dispatched parallel compute for the Pedersen DKG
// Round 1 hot path.
//
// The R_q^k Pedersen commit construction (dkg2.go Round1WithSeed Step 4)
// and the Horner share evaluation (Step 5) are both embarrassingly
// parallel across the per-coefficient and per-recipient axes:
//
//   Step 4: commits[k] = A·NTT(c_k) + B·NTT(r_k)
//           - The NTT calls (2·t·N) are independent across k.
//           - The MatrixVectorMul calls (2·t) are independent across k.
//           - The VectorAdd calls (t) write to disjoint commits[k] cells.
//           => Parallel across the k axis (length t = threshold).
//
//   Step 5: shares[j] = hornerEval(c_coeffs, j+1)
//           blinds[j] = hornerEval(r_coeffs, j+1)
//           - Each j is independent (reads coeffs, writes shares[j]/blinds[j]).
//           => Parallel across the j axis (length n = committee size).
//
// Byte-equality contract.
//
// The Gaussian sampling step (Steps 2-3) consumes a deterministic
// KeyedPRNG stream in a fixed order; we DO NOT touch that sampling path
// because changing read order changes byte output and breaks the C++
// cross-runtime KAT. Steps 4 and 5 are pure functions of the already-
// sampled coefficient vectors; their outputs are byte-equal regardless
// of the goroutine scheduling because:
//
//   - NTT is a deterministic linear transform of the coefficient vector.
//   - MatrixVectorMul is a sum of MulCoeffsMontgomeryThenAdd ops; the
//     ring routines are deterministic and the per-output-slot reduction
//     order is fixed inside MatrixVectorMul.
//   - VectorAdd writes element-wise, no cross-element reductions.
//   - Horner-method polynomial evaluation is a fixed sequence of polyMul
//     + polyAdd per `vi` slot, independent across `j`.
//
// Goroutine scheduling determines the WALL-CLOCK order of writes to
// different cells; it does not change the value written to any one
// cell.
//
// Backend selection.
//
// Same dispatch policy as the pulsar/dkg path: a build-tag flips
// dkg2GPUEnabled; the runtime selector consults GOMAXPROCS and the
// input shape (n, t). The actual luxfi/accel session (Metal/CUDA) is
// reserved for the engine layer; the in-package "GPU" today is the Go
// goroutine fan-out across independent work axes. The dispatch hook
// remains in place for the v0.6+ NIST submission lift where the accel
// MatrixVectorMul kernel becomes available.

import (
	"runtime"
	"sync"

	"github.com/luxfi/corona/sign"
	"github.com/luxfi/corona/utils"
	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/structs"
)

// dkg2ComputeBackend identifies the active compute backend.
type dkg2ComputeBackend uint8

const (
	// kDKG2BackendCPU is the single-threaded reference path. Byte-equal to
	// the historical dkg2.go Round1WithSeed.
	kDKG2BackendCPU dkg2ComputeBackend = iota

	// kDKG2BackendParallel runs the per-coefficient and per-recipient
	// fan-out across runtime.GOMAXPROCS workers.
	kDKG2BackendParallel
)

// dkg2GPUEnabled flips between CPU-only and the parallel fan-out path.
// Set by the build-tagged init() files (dkg2_gpu_accel.go for `-tags gpu`,
// dkg2_gpu_default.go for everything else).
var dkg2GPUEnabled bool

// SetDKG2GPUForTest forces the dispatch backend. Returns the previous
// value so tests can restore it. Test-only.
func SetDKG2GPUForTest(on bool) bool {
	prev := dkg2GPUEnabled
	dkg2GPUEnabled = on
	return prev
}

// DKG2GPUDispatchAvailable reports whether the GPU dispatch path is wired
// in this build.
func DKG2GPUDispatchAvailable() bool {
	return dkg2GPUEnabled
}

// resolveDKG2Backend selects the per-call backend.
//
// The Pedersen DKG Round 1 hot path is heavy enough at production sizes
// (n=21, t=14 → 196 NTT calls, 1568 MulCoeffsMontgomeryThenAdd ops,
// 2058 Horner steps) that goroutine setup is fully amortised. The
// threshold below uses NTT-call count as the shape proxy: 2·t·N where
// N is the ring degree dimension (sign.N = Nvec = 7) for the dkg2 ring.
func resolveDKG2Backend(n, t int) dkg2ComputeBackend {
	if !dkg2GPUEnabled {
		return kDKG2BackendCPU
	}
	if runtime.GOMAXPROCS(0) < 2 {
		return kDKG2BackendCPU
	}
	// 2·t·sign.N independent NTT calls plus t MatrixVectorMul plus
	// 2·n Horner chains. Below this threshold the goroutine setup
	// dwarfs the work. Empirically tuned on Apple M1 Max — the
	// crossover sits between n=3, t=2 (38 NTTs, 14 ops total) and
	// n=5, t=3 (70 NTTs). We pin at 60 NTT-calls.
	const kDKG2ParallelMinNTTs = 60
	if 2*t*sign.N < kDKG2ParallelMinNTTs {
		return kDKG2BackendCPU
	}
	return kDKG2BackendParallel
}

// computePedersenCommits builds commits[k] = A·NTT(c_k) + B·NTT(r_k) for
// k ∈ [0, t). The CPU leg is byte-identical to the inline Step 4 loop in
// dkg2.go; the parallel leg fans out across the k axis.
//
// Caller owns cCoeffs and rCoeffs (standard form, not NTT) and must NOT
// mutate them — this function CopyNews before transforming.
func computePedersenCommits(
	r *ring.Ring,
	A, B structs.Matrix[ring.Poly],
	cCoeffs, rCoeffs []structs.Vector[ring.Poly],
) []structs.Vector[ring.Poly] {
	t := len(cCoeffs)
	commits := make([]structs.Vector[ring.Poly], t)

	switch resolveDKG2Backend(0 /*n unused for commits*/, t) {
	case kDKG2BackendParallel:
		// Fan-out across the (kind ∈ {A·c, B·r}) × k product. That gives
		// 2·t independent half-commits (each contributing one Vector[Poly]
		// summand to commits[k]). Workers write to disjoint slots; a
		// single-threaded VectorAdd folds the pairs together at the end,
		// keeping the addition order byte-deterministic.
		acSlots := make([]structs.Vector[ring.Poly], t)
		brSlots := make([]structs.Vector[ring.Poly], t)
		type halfJob struct {
			isB bool
			k   int
		}
		jobs := make([]halfJob, 0, 2*t)
		for k := 0; k < t; k++ {
			jobs = append(jobs, halfJob{isB: false, k: k})
			jobs = append(jobs, halfJob{isB: true, k: k})
		}
		workers := runtime.GOMAXPROCS(0)
		if workers > len(jobs) {
			workers = len(jobs)
		}
		var wg sync.WaitGroup
		wg.Add(workers)
		for w := 0; w < workers; w++ {
			go func(w int) {
				defer wg.Done()
				for idx := w; idx < len(jobs); idx += workers {
					jb := jobs[idx]
					if jb.isB {
						brSlots[jb.k] = mulMatByNTT(r, B, rCoeffs[jb.k])
					} else {
						acSlots[jb.k] = mulMatByNTT(r, A, cCoeffs[jb.k])
					}
				}
			}(w)
		}
		wg.Wait()
		// Fold the half-commits in single-threaded VectorAdd order; this
		// is the same addition order the CPU leg uses (ac + br per k),
		// so the byte output is identical.
		for k := 0; k < t; k++ {
			commits[k] = utils.InitializeVector(r, sign.M)
			utils.VectorAdd(r, acSlots[k], brSlots[k], commits[k])
		}
	default:
		for k := 0; k < t; k++ {
			commits[k] = singleCommit(r, A, B, cCoeffs[k], rCoeffs[k])
		}
	}
	return commits
}

// mulMatByNTT computes M · NTT(coeffs) and returns the result. The
// CopyNew + NTT pair matches the historical inline loop (dkg2.go Step 4
// lines 415-419) so the output is byte-equal.
func mulMatByNTT(r *ring.Ring, M structs.Matrix[ring.Poly], coeffs structs.Vector[ring.Poly]) structs.Vector[ring.Poly] {
	nttVec := make(structs.Vector[ring.Poly], sign.N)
	for i := 0; i < sign.N; i++ {
		nttVec[i] = *coeffs[i].CopyNew()
		r.NTT(nttVec[i], nttVec[i])
	}
	out := utils.InitializeVector(r, sign.M)
	utils.MatrixVectorMul(r, M, nttVec, out)
	return out
}

// singleCommit is the per-k inner kernel: NTT the coefficients, multiply
// by A and B, sum. Byte-identical to the inline loop body in dkg2.go
// Step 4 lines 411-426.
func singleCommit(
	r *ring.Ring,
	A, B structs.Matrix[ring.Poly],
	cCoeffsK, rCoeffsK structs.Vector[ring.Poly],
) structs.Vector[ring.Poly] {
	cNTT := make(structs.Vector[ring.Poly], sign.N)
	rNTT := make(structs.Vector[ring.Poly], sign.N)
	for i := 0; i < sign.N; i++ {
		cNTT[i] = *cCoeffsK[i].CopyNew()
		r.NTT(cNTT[i], cNTT[i])
		rNTT[i] = *rCoeffsK[i].CopyNew()
		r.NTT(rNTT[i], rNTT[i])
	}
	ac := utils.InitializeVector(r, sign.M)
	utils.MatrixVectorMul(r, A, cNTT, ac)
	br := utils.InitializeVector(r, sign.M)
	utils.MatrixVectorMul(r, B, rNTT, br)
	out := utils.InitializeVector(r, sign.M)
	utils.VectorAdd(r, ac, br, out)
	return out
}

// computeHornerShares evaluates f_i(j+1) and g_i(j+1) for j ∈ [0, n). The
// CPU leg matches the inline Step 5 loop. The parallel leg fans out across
// the j axis: each goroutine owns its shares[j] and blinds[j] cells.
//
// hornerEvalFn is injected so the package's existing hornerEval stays the
// only big.Int / polyMulScalar / polyAddCoeffwise call site (the same
// invariant the audit footprint requires).
func computeHornerShares(
	r *ring.Ring,
	cCoeffs, rCoeffs []structs.Vector[ring.Poly],
	n int,
	hornerEvalFn func(r *ring.Ring, coeffs []structs.Vector[ring.Poly], j int) structs.Vector[ring.Poly],
) (shares, blinds map[int]structs.Vector[ring.Poly]) {
	shares = make(map[int]structs.Vector[ring.Poly], n)
	blinds = make(map[int]structs.Vector[ring.Poly], n)

	switch resolveDKG2Backend(n, len(cCoeffs)) {
	case kDKG2BackendParallel:
		// Pre-allocate slot arrays so workers write to distinct cells
		// without needing a synchronized map. The map[] copy at the end
		// is a single-threaded fold and stays byte-deterministic.
		shareSlots := make([]structs.Vector[ring.Poly], n)
		blindSlots := make([]structs.Vector[ring.Poly], n)

		// Fan out across the (kind ∈ {share, blind}) × j product. That
		// gives 2·n independent work items so on a 10-core box at n=14
		// we keep every core busy (28 items / 10 workers = ~3 items
		// each). On smaller n (3, 5, 7) the 2·n product still gives
		// enough cells to amortise the fan-out cost.
		type job struct {
			isBlind bool
			j       int
		}
		jobs := make([]job, 0, 2*n)
		for j := 0; j < n; j++ {
			jobs = append(jobs, job{isBlind: false, j: j})
			jobs = append(jobs, job{isBlind: true, j: j})
		}

		workers := runtime.GOMAXPROCS(0)
		if workers > len(jobs) {
			workers = len(jobs)
		}
		var wg sync.WaitGroup
		wg.Add(workers)
		for w := 0; w < workers; w++ {
			go func(w int) {
				defer wg.Done()
				for idx := w; idx < len(jobs); idx += workers {
					jb := jobs[idx]
					if jb.isBlind {
						blindSlots[jb.j] = hornerEvalFn(r, rCoeffs, jb.j)
					} else {
						shareSlots[jb.j] = hornerEvalFn(r, cCoeffs, jb.j)
					}
				}
			}(w)
		}
		wg.Wait()
		// Single-threaded fold into map form (matches existing return shape).
		for j := 0; j < n; j++ {
			shares[j] = shareSlots[j]
			blinds[j] = blindSlots[j]
		}
	default:
		for j := 0; j < n; j++ {
			shares[j] = hornerEvalFn(r, cCoeffs, j)
			blinds[j] = hornerEvalFn(r, rCoeffs, j)
		}
	}
	return shares, blinds
}
