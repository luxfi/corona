# Corona — Family Architecture

> Where Corona sits in the Lux post-quantum threshold-signature
> family. Companion to `SUBMISSION.md`, `SPEC.md`, and
> `docs/mptc/design-decisions.md`.

## §1 The three-library family

Lux ships three post-quantum threshold signature libraries with
distinct lattice families and use cases:

| Library | Lattice | Role | NIST MPTC class | Repository |
|---|---|---|---|---|
| **Corona** (this) | Ring-LWE (`R_q`) | Consensus-finality threshold (Quasar R-LWE finality kernel) | N1 + N4 (construction-level) | `luxfi/corona` |
| **Pulsar** | Module-LWE (`R_q^k × R_q^l`) | Identity-layer threshold + FIPS 204 byte-equality | N1 + N4 (FIPS-anchored) | `luxfi/pulsar` |
| **Magnetar** (research) | SLH-DSA (FIPS 205) | Hash-based fallback (research-stage) | not submitted at this writing | `luxfi/magnetar` |

Each library is independently complete. They do NOT share Go types;
they do NOT import each other; they CAN be composed at the consumer
layer (e.g., QuasarCert combines Corona + Pulsar + BLS).

## §2 Why three libraries (not one configurable kernel)?

| Decomposition axis | Choice rationale |
|---|---|
| Per-lattice-family library | A break in one lattice family (R-LWE vs M-LWE vs hash-based) should not break the others. Independent libraries with no shared types is the safest decomposition for defence-in-depth. |
| No shared types | Pulsar and Corona share NO Go types. If a vulnerability is found in Corona, the fix landing in Corona does not touch Pulsar (and vice versa). Each library's go.mod is independent. |
| Separate KAT vectors | Pulsar's KATs target FIPS 204 byte-equality. Corona's KATs target Go ↔ C++ cross-runtime byte-equality. The two KAT formats are intentionally different (different lattice algebra; different signature byte layouts). |
| Separate hash-suite registries | Pulsar uses SHAKE / cSHAKE / KMAC per FIPS 204 layouts. Corona uses cSHAKE256 / KMAC256 / TupleHash256 per FIPS 202 + SP 800-185 with `CORONA-*` customization strings. Even though the underlying primitives overlap, the domain-separation registries are disjoint. |

## §3 Composition surface — QuasarCert

A consumer (Lux primary-network QuasarCert) MAY combine Corona +
Pulsar + classical BLS + per-validator ML-DSA into a **Double
Lattice** layered certificate:

```
QuasarCert {
    BLS         — classical fast-path (BLS-12-381 aggregate); pre-quantum
    Corona      — Ring-LWE   threshold (this repo)            ; PQ kernel A
    Pulsar      — Module-LWE threshold (luxfi/pulsar)         ; PQ kernel B
    MLDSARollup — per-validator ML-DSA-65 rolled up via P3Q   ; PQ accountability
}
```

Each layer is checkable independently:
- BLS: any pairing-aware verifier accepts.
- Corona: `sign.Verify` accepts.
- Pulsar: any FIPS 204 ML-DSA verifier accepts (the byte-equal claim).
- MLDSARollup: STARK / FRI verifier accepts via the P3Q backend.

Selecting which layers are included happens at chain-construction
time via the `FinalitySchemeID` axis. A pure-PQ profile drops BLS
and runs on Corona + Pulsar + MLDSARollup. A classical-fast profile
runs BLS only. A hybrid profile runs all four.

This composition is the CONSUMER's design choice, not Corona's. The
Corona submission stands alone as an N1 + N4 candidate; reviewers
do NOT need to evaluate the QuasarCert composition.

## §4 Relationship to LSS (the orchestration framework)

`~/work/lux/threshold/protocols/lss/` is Lux's generic dynamic-
threshold lifecycle framework, paper-backed by Seesahai 2025.

LSS owns:
- Generation numbers and version monotonicity (`Generation`,
  `RollbackFrom`).
- Live resharing orchestration (Section 4 of the LSS paper).
- Bootstrap Dealer / Signature Coordinator role separation.
- `RollbackManager` and `GenerationSnapshot` history.

LSS does NOT own:
- Lattice math (Pedersen `R_q^M` commits, NTT, Gaussian sampling).
- Threshold signature scheme specifics.

Corona contributes the lattice math via the adapter pattern. The
`lss_pulsar.go` adapter at `~/work/lux/threshold/protocols/lss/`
mediates between LSS's generic orchestration and Corona's lattice-
specific operations.

## §5 Layer separation

```
~/work/lux/corona/                              # CORONA MATH KERNEL (this repo)
  ├── sign/, threshold/, dkg2/, reshare/         (single-process API)
  ├── primitives/, hash/                         (cryptographic primitives)
  ├── keyera/                                    (kernel-level lifecycle)
  └── cmd/*_oracle*/                             (KAT generation)

~/work/lux/threshold/protocols/lss/             # ORCHESTRATION FRAMEWORK
  ├── DynamicLSS, RollbackManager, JVSS          (generic, paper-backed)
  ├── lss_frost.go: DynamicReshareFROST          (Schnorr/EdDSA adapter)
  ├── lss_cmp.go: DynamicReshareCMP              (ECDSA adapter)
  └── lss_pulsar.go: DynamicResharePulsar        (lattice adapter; uses Corona)

~/work/lux/consensus/protocol/quasar/           # CONSENSUS LAYER
  └── epoch.go                                   (consumes Corona via LSS adapter)
```

## §6 The pulsar-vs-corona-vs-quasar nomenclature

Naming history (from `LLM.md` and `DESIGN.md`):
- **Quasar** — the leaderless permissionless consensus protocol that
  consumes all PQ primitives. Lives at
  `~/work/lux/consensus/protocol/quasar/`.
- **Pulsar** — the M-LWE threshold ML-DSA library at `luxfi/pulsar`.
  Named for the rotating-neutron-star metaphor: persistent group
  key, rotating share distribution.
- **Corona** — the R-LWE threshold library (this repo). Named for
  the luminous ring of light surrounding a star, brand-paired with
  Pulsar at a different lattice layer.

A historical rename from `Pulsar` → `Corona` happened in 2026 when
the M-LWE work picked up the `Pulsar` name and the R-LWE work
retained the pulsar metaphor under the `Corona` brand. The
`papers/lp-073-pulsar/` directory retains the old name; the LaTeX
sections inside refer to the R-LWE construction (now called Corona)
under the historical paper name LP-073.

## §7 Two distinct primitives, one lifecycle

Corona ships TWO distinct primitives, NOT one fuzzy "Reshare":

| Primitive | Defends against | Same set or new? |
|---|---|---|
| `Refresh` | Mobile-adversary share accumulation | SAME committee |
| `ReshareToNewSet` | Validator-set rotation | NEW committee |

Both preserve `(A, bTilde)` within a key era. Both follow the same
3-round wire shape (commitments → private deliveries → combine +
activate). Both gate new-epoch acceptance on the activation cert
circuit-breaker. They differ in WHO holds the new shares.

A consumer that fails to distinguish them at the API level is
likely to misuse one or the other; the dedicated function names
force the distinction.

## §8 Three layers, one shipping path

| Layer | Operation | Trigger | Trust |
|---|---|---|---|
| 1. **Bootstrap** | trusted-dealer `Gen(s, A, e) → (bTilde, shares)` | Chain genesis, ONCE per key era | Foundation MPC ceremony |
| 2. **Reshare** | preserves `(s, bTilde, GroupKey)`; rotates share distribution | Every epoch with validator-set change | NO new trust; old qualified subset cooperates |
| 3. **Reanchor** | new `(s', A', e', bTilde')` | Rare governance event | Same as Bootstrap |

What is preserved across Reshare WITHIN a key era:
- `A` (public matrix) — preserved
- `s` (hidden signing secret) — preserved (share distribution rotates)
- `bTilde` (rounded public key) — preserved
- `GroupKey = (A, bTilde)` — byte-identical preserved
- `e` (LWE error) — NOT preserved (used at genesis only; signers
  need shares of `s`, not `e`)

What is preserved across Reanchor:
- The chain identity (chain_id, network_id).
- NOTHING else from the previous key era.

## §9 Relationship to the upstream academic construction

Boschini, Kaviani, Lai, Malavolta, Takahashi, Tibouchi (IACR ePrint
2024/1113, IEEE S&P 2025) published the 2-round R-LWE threshold
signature construction. The paper specifies:
- The 2-round signing protocol (Round 1 commit + Round 2 response +
  Combine).
- The verifier.
- The trusted-dealer Gen (assumed; not Lux-novel).
- The EUF-CMA reduction.

The paper does NOT specify:
- Public DKG (Lux contributed `dkg2/` Pedersen DKG over `R_q`).
- Proactive resharing (Lux contributed `reshare/`).
- Identifiable abort with attributable evidence.
- Activation cert circuit-breaker.
- Hash-suite injection architecture.
- Cross-runtime byte-equality manifest enforcement.
- Production deployment runbook.

Corona's contribution is the production lifecycle layered atop the
published construction. The cryptographic core (2-round signing
math) is faithfully implemented from the paper; the production
layer is Lux-novel.

## §10 The lens / Magnetar relationship (NOT in scope)

`lens/` is a separate Lux library for curve-based threshold signing
(Ed25519, secp256k1, Ristretto255). It is mentioned in
`CONSTANT-TIME-REVIEW.md` §5 because it shares some code paths with
Corona's reshare layer (specifically the curve-Lagrange utilities).
Corona's threshold path does NOT depend on lens; lens is a sibling
library, not a Corona dependency.

`magnetar/` is the SLH-DSA (FIPS 205) research-stage threshold
library. It is mentioned in `SUBMISSION.md` for completeness but
is NOT in scope for the Corona submission package.

---

**Document metadata**

- Name: `docs/mptc/family-architecture.md`
- Version: v0.1 (initial submission-package scaffolding)
- Date: 2026-05-18
