// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keyera

import (
	"io"

	"github.com/luxfi/corona/hash"
)

// ReanchorPedersen opens a new key era WITHOUT a trusted dealer.
//
// This is the public-BFT-safe Reanchor entrypoint: the keygen ceremony
// for the new era routes through dkg2/ (Pedersen-DKG over R_q) + Path
// (a) noise flooding, exactly like BootstrapPedersen does at chain
// genesis. No party ever holds the master secret s for the new era at
// any point in the rotation. The previous era's GroupKey is discarded
// (Reanchor is the only lifecycle operation that may do so).
//
// Reanchor inherits the prior era's HashSuiteID. To migrate to a
// different suite (e.g. moving from legacy Corona-BLAKE3 to production
// Corona-SHA3) call ReanchorPedersenWithSuite.
//
// Use ONLY for security-event response — long-tail share leakage,
// suspected master-secret compromise, etc. The chain governance MUST
// authorize this; it is not a routine operation. For ordinary
// validator-set rotation use Reshare, which preserves the GroupKey.
//
// On identifiable abort returns (nil, nil, ErrBootstrapPedersenAbort)
// with the AbortEvidence wrapped into the returned error; chain stays
// at the previous era. Extract via ExtractAbortEvidence.
//
// Returns the new *KeyEra (EraID = prev.EraID+1, GenesisEpoch =
// prev.State.Epoch+1), the public *BootstrapTranscript for chain
// commit, and nil on success.
//
// See DEPLOYMENT-RUNBOOK.md §Bootstrap-Trust for the trust-model
// trade-off documentation (which entry to use when).
func ReanchorPedersen(prev *KeyEra, t int, validators []string, groupID CoronaGroupID, entropy io.Reader) (*KeyEra, *BootstrapTranscript, error) {
	var suite hash.HashSuite
	if prev != nil && prev.HashSuiteID == hash.LegacyBLAKE3ID {
		suite = hash.NewCoronaBLAKE3()
	} else {
		suite = hash.Default()
	}
	return ReanchorPedersenWithSuite(prev, suite, t, validators, groupID, entropy)
}

// ReanchorPedersenWithSuite opens a new key era under the supplied
// HashSuite via Pedersen-DKG + Path (a) noise flooding. Reanchor is
// the ONLY lifecycle entrypoint that may pin a hash profile different
// from the prior era's (Reshare cannot — that is enforced by Reshare
// not accepting a suite parameter). Pass nil to use the production
// default (Corona-SHA3).
//
// The key-era boundary semantics match ReanchorWithSuite (the legacy
// trusted-dealer variant): the new era's EraID is prev.EraID+1, and
// both GenesisEpoch and State.Epoch are set to prev.State.Epoch+1 so
// the monotonic-epoch invariant holds across the rotation. Only the
// underlying DKG mechanism changes — every consumer downstream of the
// returned KeyEra is byte-equivalent to a fresh BootstrapPedersen run
// at era ID prev.EraID+1.
func ReanchorPedersenWithSuite(prev *KeyEra, suite hash.HashSuite, t int, validators []string, groupID CoronaGroupID, entropy io.Reader) (*KeyEra, *BootstrapTranscript, error) {
	var nextEraID CoronaKeyEraID
	var nextEpoch uint64
	if prev != nil {
		nextEraID = prev.EraID + 1
		if prev.State != nil {
			nextEpoch = prev.State.Epoch + 1
		}
	}
	next, transcript, err := BootstrapPedersen(suite, t, validators, groupID, nextEraID, entropy)
	if err != nil {
		return nil, nil, err
	}
	next.GenesisEpoch = nextEpoch
	next.State.Epoch = nextEpoch
	return next, transcript, nil
}
