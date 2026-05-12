# Corona

> Lux is not merely adding post-quantum signatures to a chain; it defines a hybrid finality architecture for DAG-native consensus, with protocol-agnostic threshold lifecycle, post-quantum threshold sealing, and cross-chain propagation of Horizon finality.

See [LP-105 §Claims and evidence](https://github.com/luxfi/lps/blob/main/LP-105-lux-stack-lexicon.md#claims-and-evidence) for the canonical claims/evidence table and the ten architectural commitments — single source of truth.

**Corona** is the Lux **Ring-LWE** post-quantum threshold signature library
for **Quasar consensus**. The 2-round threshold construction line traces back
to Boschini–Kaviani–Lai–Malavolta–Takahashi–Tibouchi's academic R-LWE paper
(ePrint 2024/1113); the academic codebase lives at
[`luxfi/nasua`](https://github.com/luxfi/nasua) (historical reference fork,
trusted-dealer DKG only — not for public-chain use). Corona adds the
production lifecycle that fork lacked: Pedersen DKG over `R_q` with proper
hiding, proactive resharing for epoch validator rotation, identifiable
abort, and the integration surface Quasar consumes.

The **Module-LWE sibling library** lives at [`luxfi/pulsar`](https://github.com/luxfi/pulsar).
Pulsar's threshold signature output is byte-equal to FIPS 204 single-party
ML-DSA (NIST MPTC Class N1). The two libraries are independent — there is
no import line between them — and Quasar consumes them as parallel kernels
selected per-chain via `FinalitySchemeID`.

## Version note

This repository owns the former `luxfi/pulsar` `v0.1.x` Ring-LWE code line.
Following the 2026 Pulsar / Corona split:

- **Ring-LWE** code (this repository) retains `v0.1.0`, `v0.1.1`, `v0.1.2`,
  `v0.1.5` as historical R-LWE releases under their new home, and continues
  with `v0.2.0` onward as the post-split Corona line.
- **Module-LWE** code moved to [`luxfi/pulsar`](https://github.com/luxfi/pulsar)
  and starts at `v1.0.0` to signal the identity break.

Use:

```sh
go get github.com/luxfi/corona@v0.2.0         # Ring-LWE (this repo, post-split)
go get github.com/luxfi/pulsar@v1.0.0         # Module-LWE (sibling repo)
```

## Why "Corona"

A corona is the luminous ring of light surrounding a star — visible only
when the brighter central body (the Pulsar / Quasar) is partially occluded.
Brand-paired with Pulsar (Module-LWE) and Quasar (the consensus that
consumes both): the same family of threshold-finality light, observed at
a different layer.

## Relationship to academic Nasua (formerly upstream Ringtail)

[`luxfi/nasua`](https://github.com/luxfi/nasua) holds the academic
2-round R-LWE threshold construction (Boschini et al, ePrint 2024/1113)
as a **historical reference fork** — "not ready for production use" per
its origin. Corona is the production track:

| Layer | Academic Nasua | Corona |
|---|---|---|
| 2-round threshold sign | ✅ same byte-equal protocol | ✅ inherited |
| Trusted-dealer Gen | ✅ for fixed federation | ✅ retained for bridge MPC |
| **Proactive resharing** for epoch validator rotation | ❌ not specified | 🚧 **corona/reshare/** (this fork) |
| **Pedersen DKG over R_q** with proper hiding | ❌ not specified | 🚧 **corona/dkg2/** (this fork) |
| Per-validator triple-sign integration with Quasar | ❌ N/A | 🚧 **corona/consensus/** integration |

## Composition with Pulsar as optional layered PQ defense

Corona is independently usable: a chain can pick Ring-LWE Corona as its
sole PQ threshold layer, no cross-dependency on Pulsar. Lux primary-
network QuasarCert combines both lattice families as a **Double Lattice**
layered defence so a break in one family does not break finality:

```
QuasarCert {
    BLS         — optional classical fast-path (BLS-12-381 aggregate)
    Corona      — Ring-LWE   threshold ML-DSA (this repo)
    Pulsar      — Module-LWE threshold ML-DSA (luxfi/pulsar)
    MLDSARollup — per-validator ML-DSA-65 rolled up via STARK/FRI (P3Q)
}
```

Each layer is checkable independently with no shared code; selecting
the layer happens at chain-construction time via the `FinalitySchemeID`
axis on the chain's `ChainSecurityProfile`. The pure-PQ profile drops
BLS entirely and runs on `Corona + Pulsar`.

## Layout

- `sign/` — 2-round threshold signing (byte-equal with upstream)
- `primitives/` — Shamir, hashes, MACs, PRFs (byte-equal with upstream)
- `utils/` — NTT, Montgomery, ring helpers (byte-equal with upstream)
- `networking/` — TCP peer-to-peer (byte-equal with upstream)
- `dkg/` — original Lux DKG (Feldman VSS without noise; **broken** for public broadcast — see RED-DKG-REVIEW). Retained for reference.
- `dkg2/` — proper Pedersen DKG over R_q (Pulsar addition; this fork)
- `reshare/` — proactive secret resharing for epoch rotation (Pulsar addition; this fork)
- `cmd/` — KAT oracle generators

## Status

WIP. The 2-round Sign+Verify path is byte-equal-validated against the academic Ringtail spec via 16 SHA-256 KATs. The Pulsar-specific additions (resharing + Pedersen DKG) are under design and implementation.
