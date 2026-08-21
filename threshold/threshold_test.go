// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package threshold

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestGenerateKeysTrustedDealer(t *testing.T) {
	shares, groupKey, err := GenerateKeysTrustedDealer(2, 3, nil)
	if err != nil {
		t.Fatalf("GenerateKeysTrustedDealer failed: %v", err)
	}

	if len(shares) != 3 {
		t.Errorf("expected 3 shares, got %d", len(shares))
	}
	if groupKey == nil {
		t.Fatal("groupKey is nil")
	}
	if groupKey.A == nil {
		t.Error("groupKey.A is nil")
	}
	if groupKey.BTilde == nil {
		t.Error("groupKey.BTilde is nil")
	}

	for i, share := range shares {
		if share.Index != i {
			t.Errorf("share %d has index %d", i, share.Index)
		}
		if share.GroupKey != groupKey {
			t.Errorf("share %d has wrong groupKey", i)
		}
	}
}

func TestThresholdSigningFlow(t *testing.T) {
	// Generate 2-of-3 threshold keys
	shares, groupKey, err := GenerateKeysTrustedDealer(2, 3, nil)
	if err != nil {
		t.Fatalf("GenerateKeysTrustedDealer failed: %v", err)
	}

	// Create signers for all parties
	signers := make([]*Signer, 3)
	for i, share := range shares {
		signers[i] = NewSigner(share)
	}

	// Signing parameters
	sessionID := 1
	prfKey := []byte("test-prf-key-32-bytes-long!!!!!!")
	signerIDs := []int{0, 1, 2}
	message := "test block hash for consensus"

	// Round 1: All parties compute D + MACs
	round1Data := make(map[int]*Round1Data)
	for _, signer := range signers {
		data, err := signer.Round1(sessionID, prfKey, signerIDs)
		if err != nil {
			t.Fatalf("Round1: %v", err)
		}
		round1Data[data.PartyID] = data
		t.Logf("Party %d: Round1 complete, D size: %d x %d", data.PartyID, len(data.D), len(data.D[0]))
	}

	// Round 2: All parties compute z shares
	round2Data := make(map[int]*Round2Data)
	for _, signer := range signers {
		data, err := signer.Round2(sessionID, message, prfKey, signerIDs, round1Data)
		if err != nil {
			t.Fatalf("Party %d Round2 failed: %v", signer.share.Index, err)
		}
		round2Data[data.PartyID] = data
		t.Logf("Party %d: Round2 complete, z size: %d", data.PartyID, len(data.Z))
	}

	// Finalize: Any party can aggregate
	sig, err := signers[0].Finalize(round2Data)
	if err != nil {
		t.Fatalf("Finalize failed: %v", err)
	}
	t.Logf("Signature: C degree=%d, Z size=%d, Delta size=%d", sig.C.N(), len(sig.Z), len(sig.Delta))

	// Verify
	valid := Verify(groupKey, message, sig)
	if !valid {
		t.Error("signature verification failed")
	}
	t.Log("✓ Signature verified successfully")
}

func TestThresholdWrongMessage(t *testing.T) {
	shares, groupKey, err := GenerateKeysTrustedDealer(2, 3, nil)
	if err != nil {
		t.Fatalf("GenerateKeysTrustedDealer failed: %v", err)
	}

	signers := make([]*Signer, 3)
	for i, share := range shares {
		signers[i] = NewSigner(share)
	}

	sessionID := 1
	prfKey := []byte("test-prf-key-32-bytes-long!!!!!!")
	signerIDs := []int{0, 1, 2}
	message := "original message"

	// Round 1
	round1Data := make(map[int]*Round1Data)
	for _, signer := range signers {
		data, err := signer.Round1(sessionID, prfKey, signerIDs)
		if err != nil {
			t.Fatalf("Round1: %v", err)
		}
		round1Data[data.PartyID] = data
	}

	// Round 2
	round2Data := make(map[int]*Round2Data)
	for _, signer := range signers {
		data, _ := signer.Round2(sessionID, message, prfKey, signerIDs, round1Data)
		round2Data[data.PartyID] = data
	}

	// Finalize
	sig, _ := signers[0].Finalize(round2Data)

	// Verify with wrong message should fail
	valid := Verify(groupKey, "wrong message", sig)
	if valid {
		t.Error("verification should fail for wrong message")
	}
}

// TestFinalize_DuplicatePartyID_Rejected feeds two Round2 inputs carrying
// the same PartyID into Finalize and asserts the kernel-boundary guard
// rejects them with ErrDuplicateSigner instead of silently overwriting the
// duplicated z share (which would double-count one signer).
func TestFinalize_DuplicatePartyID_Rejected(t *testing.T) {
	shares, _, err := GenerateKeysTrustedDealer(2, 3, nil)
	if err != nil {
		t.Fatalf("GenerateKeys failed: %v", err)
	}

	signers := make([]*Signer, 3)
	for i, share := range shares {
		signers[i] = NewSigner(share)
	}

	sessionID := 1
	prfKey := []byte("test-prf-key-32-bytes-long!!!!!!")
	signerIDs := []int{0, 1, 2}
	message := "test block hash for consensus"

	round1Data := make(map[int]*Round1Data)
	for _, signer := range signers {
		data, err := signer.Round1(sessionID, prfKey, signerIDs)
		if err != nil {
			t.Fatalf("Round1: %v", err)
		}
		round1Data[data.PartyID] = data
	}

	round2Data := make(map[int]*Round2Data)
	for _, signer := range signers {
		data, err := signer.Round2(sessionID, message, prfKey, signerIDs, round1Data)
		if err != nil {
			t.Fatalf("Round2: %v", err)
		}
		round2Data[data.PartyID] = data
	}

	// Inject a duplicate: a distinct map key whose payload carries a
	// PartyID already present in the set. This is exactly what a buggy or
	// malicious caller that violated the quorum-uniqueness invariant would
	// produce, and what the collect-loop guard must reject.
	dup := &Round2Data{PartyID: round2Data[0].PartyID, Z: round2Data[0].Z}
	round2Data[99] = dup

	_, err = signers[0].Finalize(round2Data)
	if err != ErrDuplicateSigner {
		t.Fatalf("expected ErrDuplicateSigner, got %v", err)
	}
}

// TestRound2_DuplicatePartyID_Rejected mirrors the duplicate-PartyID guard
// for the Round 2 combine, where a repeated PartyID would overwrite the D
// matrix / MAC entry collected for that party.
func TestRound2_DuplicatePartyID_Rejected(t *testing.T) {
	shares, _, err := GenerateKeysTrustedDealer(2, 3, nil)
	if err != nil {
		t.Fatalf("GenerateKeys failed: %v", err)
	}

	signers := make([]*Signer, 3)
	for i, share := range shares {
		signers[i] = NewSigner(share)
	}

	sessionID := 1
	prfKey := []byte("test-prf-key-32-bytes-long!!!!!!")
	signerIDs := []int{0, 1, 2}
	message := "test block hash for consensus"

	round1Data := make(map[int]*Round1Data)
	for _, signer := range signers {
		data, err := signer.Round1(sessionID, prfKey, signerIDs)
		if err != nil {
			t.Fatalf("Round1: %v", err)
		}
		round1Data[data.PartyID] = data
	}

	// Inject a duplicate Round1 payload under a fresh map key so len() still
	// satisfies the insufficient-data check and the collect loop sees the
	// repeated PartyID.
	round1Data[99] = &Round1Data{
		PartyID: round1Data[0].PartyID,
		D:       round1Data[0].D,
		MACs:    round1Data[0].MACs,
	}

	_, err = signers[0].Round2(sessionID, message, prfKey, signerIDs, round1Data)
	if err != ErrDuplicateSigner {
		t.Fatalf("expected ErrDuplicateSigner, got %v", err)
	}
}

func TestInvalidThreshold(t *testing.T) {
	// Threshold >= total
	_, _, err := GenerateKeysTrustedDealer(3, 3, nil)
	if err != ErrInvalidThreshold {
		t.Errorf("expected ErrInvalidThreshold, got %v", err)
	}

	// Threshold = 0
	_, _, err = GenerateKeysTrustedDealer(0, 3, nil)
	if err != ErrInvalidThreshold {
		t.Errorf("expected ErrInvalidThreshold, got %v", err)
	}

	// Too few parties
	_, _, err = GenerateKeysTrustedDealer(1, 1, nil)
	if err != ErrInvalidPartyCount {
		t.Errorf("expected ErrInvalidPartyCount, got %v", err)
	}
}

// TestGroupKeyBytes_IsAContentFingerprint pins that the group-key identifier
// distinguishes distinct keys. It was only the (A, BTilde) dimensions, which
// every key of one parameter set shares, so anything keyed on it collapsed
// every Corona group into one.
func TestGroupKeyBytes_IsAContentFingerprint(t *testing.T) {
	_, a, err := GenerateKeysTrustedDealer(1, 2, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, b, err := GenerateKeysTrustedDealer(1, 2, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatalf("two distinct group keys share the identifier %x", a.Bytes())
	}
	if !bytes.Equal(a.Bytes(), a.Bytes()) {
		t.Fatal("group-key identifier is not stable across calls")
	}
	if len(a.Bytes()) != 32 {
		t.Fatalf("identifier length = %d, want a 32-byte content hash", len(a.Bytes()))
	}
}
