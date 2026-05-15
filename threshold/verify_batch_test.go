// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package threshold

import (
	"errors"
	"fmt"
	"testing"
)

// freshSig produces one (groupKey, message, sig) triple by running a
// full 2-of-3 ceremony. The verifier in this package is pure, so the
// ceremony is the only realistic way to obtain a Corona signature
// (Sign1/Sign2/Combine are the only public entry points).
func freshSig(t testing.TB, message string) (*GroupKey, *Signature) {
	t.Helper()
	shares, groupKey, err := GenerateKeys(2, 3, nil)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	signers := make([]*Signer, 3)
	for i, share := range shares {
		signers[i] = NewSigner(share)
	}
	const sessionID = 1
	prfKey := []byte("verify_batch-prf-key-32-bytes!!!")
	signerIDs := []int{0, 1, 2}

	round1 := make(map[int]*Round1Data)
	for _, s := range signers {
		d := s.Round1(sessionID, prfKey, signerIDs)
		round1[d.PartyID] = d
	}
	round2 := make(map[int]*Round2Data)
	for _, s := range signers {
		d, err := s.Round2(sessionID, message, prfKey, signerIDs, round1)
		if err != nil {
			t.Fatalf("Round2: %v", err)
		}
		round2[d.PartyID] = d
	}
	sig, err := signers[0].Finalize(round2)
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	return groupKey, sig
}

// TestVerifyBatch_AllValid asserts a batch of N valid signatures all
// report true and VerifyBatchAll returns true.
func TestVerifyBatch_AllValid(t *testing.T) {
	const n = 4

	gks := make([]*GroupKey, n)
	msgs := make([]string, n)
	sigs := make([]*Signature, n)
	for i := 0; i < n; i++ {
		msg := fmt.Sprintf("corona-batch-msg-%d", i)
		gk, sig := freshSig(t, msg)
		gks[i] = gk
		msgs[i] = msg
		sigs[i] = sig
	}

	results, err := VerifyBatch(gks, msgs, sigs)
	if err != nil {
		t.Fatalf("VerifyBatch err=%v", err)
	}
	if len(results) != n {
		t.Fatalf("results len=%d, want %d", len(results), n)
	}
	for i, ok := range results {
		if !ok {
			t.Errorf("result[%d] = false, want true", i)
		}
	}

	all, err := VerifyBatchAll(gks, msgs, sigs)
	if err != nil || !all {
		t.Errorf("VerifyBatchAll ok=%v err=%v, want (true, nil)", all, err)
	}
}

// TestVerifyBatch_OneCorrupt asserts a single message-substitution
// corruption is localised: results[i] = false for the swapped entry,
// true for all the rest, and VerifyBatchAll returns false.
func TestVerifyBatch_OneCorrupt(t *testing.T) {
	const n = 3
	const badIdx = 1

	gks := make([]*GroupKey, n)
	msgs := make([]string, n)
	sigs := make([]*Signature, n)
	for i := 0; i < n; i++ {
		msg := fmt.Sprintf("corona-batch-msg-%d", i)
		gk, sig := freshSig(t, msg)
		gks[i] = gk
		msgs[i] = msg
		sigs[i] = sig
	}
	// Verify under the WRONG message for the bad index — the signature
	// was made over msgs[badIdx]; we ask the verifier to check against
	// a different string, which the FIPS 204 verifier rejects.
	msgs[badIdx] = "corona-batch-wrong-message"

	results, err := VerifyBatch(gks, msgs, sigs)
	if err != nil {
		t.Fatalf("VerifyBatch err=%v", err)
	}
	for i, ok := range results {
		if i == badIdx {
			if ok {
				t.Errorf("result[%d] = true, want false (corrupted entry)", i)
			}
		} else if !ok {
			t.Errorf("result[%d] = false, want true", i)
		}
	}

	all, err := VerifyBatchAll(gks, msgs, sigs)
	if err != nil {
		t.Fatalf("VerifyBatchAll err=%v", err)
	}
	if all {
		t.Error("VerifyBatchAll = true, want false")
	}
}

// TestVerifyBatch_StructuralMismatch asserts length-mismatched slices
// surface as ErrBatchSizeMismatch with a nil results slice.
func TestVerifyBatch_StructuralMismatch(t *testing.T) {
	gks := []*GroupKey{nil, nil}
	msgs := []string{"a", "b", "c"}
	sigs := []*Signature{nil, nil}

	results, err := VerifyBatch(gks, msgs, sigs)
	if !errors.Is(err, ErrBatchSizeMismatch) {
		t.Errorf("err = %v, want ErrBatchSizeMismatch", err)
	}
	if results != nil {
		t.Errorf("results = %v, want nil", results)
	}
}

// TestVerifyBatch_Empty asserts an empty batch is (nil, nil).
func TestVerifyBatch_Empty(t *testing.T) {
	results, err := VerifyBatch(nil, nil, nil)
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
	if results != nil {
		t.Errorf("results = %v, want nil", results)
	}
}
