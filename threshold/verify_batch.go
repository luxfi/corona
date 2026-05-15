// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package threshold

// verify_batch.go -- parallel CPU batch verifier for Corona
// (Ring-LWE 2-round threshold) signatures.
//
// Corona signatures are NOT FIPS 204 byte-equal (that's Pulsar's
// Module-LWE sibling); the wire encoding is the (C, Z, Delta) ring
// polynomial triple defined in threshold.go. Verification is the
// single sign.Verify call wrapped by Verify() in threshold.go; this
// file composes it across N (groupKey, message, signature) tuples
// in parallel.
//
// Pure-Go, no CGO: keeps Corona portable. GPU dispatch (an NTT-batch
// kernel over the verifier's polynomial-arithmetic hotspot) is a
// luxfi/accel concern; consumers that want it call accel directly
// against the same wire bytes.

import (
	"errors"
	"runtime"
	"sync"
)

// ErrBatchSizeMismatch is returned when groupKeys, messages, and sigs
// do not all have the same length.
var ErrBatchSizeMismatch = errors.New("corona: batch slices length mismatch")

// VerifyBatch verifies N (groupKey, message, signature) tuples in
// parallel. results[i] is true iff the i-th signature is valid under
// Verify(groupKeys[i], messages[i], sigs[i]).
//
// The slices MUST have equal length; mismatches return
// ErrBatchSizeMismatch with a nil results slice.
//
// Empty input (len == 0) returns (nil, nil).
//
// Parallelism is bounded by GOMAXPROCS so a caller that already has
// its own concurrency doesn't oversaturate the CPU.
//
// VerifyBatch is the canonical entry point for any consumer that
// needs to verify > 1 Corona signature. Use Verify only when N == 1.
func VerifyBatch(groupKeys []*GroupKey, messages []string, sigs []*Signature) ([]bool, error) {
	n := len(sigs)
	if n != len(groupKeys) || n != len(messages) {
		return nil, ErrBatchSizeMismatch
	}
	if n == 0 {
		return nil, nil
	}

	results := make([]bool, n)

	workers := runtime.GOMAXPROCS(0)
	if workers > n {
		workers = n
	}

	jobs := make(chan int, n)
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := range jobs {
				results[i] = Verify(groupKeys[i], messages[i], sigs[i])
			}
		}()
	}
	for i := 0; i < n; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	return results, nil
}

// VerifyBatchAll is a convenience predicate: true iff every signature
// in the batch verifies. Returns (false, err) only on the structural
// ErrBatchSizeMismatch.
func VerifyBatchAll(groupKeys []*GroupKey, messages []string, sigs []*Signature) (bool, error) {
	results, err := VerifyBatch(groupKeys, messages, sigs)
	if err != nil {
		return false, err
	}
	for _, ok := range results {
		if !ok {
			return false, nil
		}
	}
	return true, nil
}
