# Corona — Design Decisions

> Rationale for the design choices behind Corona's production
> lifecycle on top of the Boschini et al. ePrint 2024/1113 R-LWE
> threshold construction.

## §1 Why Ring-LWE (not Module-LWE)?

| Question | Answer |
|---|---|
| Why ship an R-LWE library when ML-DSA (M-LWE) is the NIST standard? | The R-LWE 2-round construction (Boschini et al. 2024/1113) was published a year before the M-LWE equivalent matured. Lux deployed the R-LWE path first because it was the only construction with a published peer-reviewed 2-round threshold signature analysis for lattice-based signatures at the time of consensus design. |
| Why keep R-LWE after the M-LWE path (Pulsar) is ready? | Lux's primary-network QuasarCert is designed to consume BOTH lattice families as a **Double Lattice** layered defence so a break in one lattice family does not break finality. The two are complementary, not interchangeable. |
| Why not converge on a single lattice family? | A break in Module-LWE (which Pulsar uses) would not automatically break Ring-LWE (which Corona uses), and vice versa. The cost is wire-size overhead (Corona certs are variable-size; Pulsar certs are fixed-size); the benefit is structural diversity. |

## §2 Why this parameter set?

| Parameter | Value | Rationale |
|---|---|---|
| Ring degree `N` | 256 | Standard choice for 128-bit post-quantum security per the lattice-estimator methodology; matches lattigo's default ring sizing for R-LWE. |
| Prime `q` | `0x1000000004A01` | 48-bit NTT-friendly prime. Wide enough to absorb the Lagrange-aggregation coefficient growth without overflow; narrow enough that single-`q` polynomial arithmetic fits in `uint64`. |
| Module width `M` | 8 | Balances signature size against security margin under R-LWE attacks. |
| Module height `N_M` | 7 | Matches `M` − 1 to give comfortable EUF-CMA reduction margin. |
| Challenge weight `Kappa` | 23 | Ternary challenge weight per Boschini et al. parameter analysis. |

A second parameter set targeting NIST PQ Category 3 is roadmap
v0.6.0; concrete lattice-estimator output for the current set is
roadmap v0.6.0.

## §3 Why Pedersen DKG (`dkg2/`) and not Feldman (`dkg/`)?

The legacy `dkg/` package uses Feldman-style commitments
`C = A · NTT(s)` without hiding blinds. This is documented broken
for public broadcast in the upstream `RED-DKG-REVIEW.md` (Findings
5/6): without hiding blinds, an observer can extract information
about `s` from the public commitment, defeating the secret-sharing
property.

`dkg2/` replaces this with proper Pedersen commits
`C^(k) = A · NTT(s^(k)) + B · NTT(r^(k))` with per-coefficient
hiding blind `r^(k)`. The hiding blind ensures the commitment leaks
no information about `s^(k)` beyond what is necessary for
verification.

The trade-off: `dkg2/` is more expensive (twice as many polynomial
multiplications per commit) but secure under public broadcast. The
legacy `dkg/` is retained ONLY for historical reference and reading
existing test fixtures; production deployments MUST use `dkg2/`.

## §4 Why two reshare primitives (`Refresh` and `ReshareToNewSet`)?

The two operations serve different purposes and have different
threat models:

| Primitive | Use case | Threat model |
|---|---|---|
| `Refresh` | Mobile-adversary defense within a stable committee | Adversary slowly compromises parties over time; Refresh forces the adversary to start over (must compromise a new t-subset within one Refresh window). |
| `ReshareToNewSet` | Validator-set rotation | New validators join, old validators leave; the new set must be able to sign under the unchanged group key. |

Lumping them into a single `Reshare` call would obscure the
distinction. `DESIGN.md` enforces the separation explicitly.

## §5 Why the activation cert circuit-breaker?

After a Reshare completes the math, three failure modes exist that
the math itself cannot detect:

1. A malicious old-set party delivered subtly malformed shares to a
   subset of new-set parties (the Pedersen verification catches
   most cases but not all under network races).
2. The new-set parties' fresh shares are inconsistent due to a
   protocol race condition.
3. The pairwise PRF/MAC material was regenerated incorrectly.

The activation cert is the chain's circuit-breaker: it forces the
new committee to PROVE they can sign under the unchanged group key
before the chain accepts them. If the proof fails, the chain falls
back to the old committee — no liveness loss, no slashing required.

This is the no-slashing-dependency property documented in
`DESIGN.md` §"Bootstrap Dealer vs Signature Coordinator (LSS roles,
no-slashing semantics)".

## §6 Why hash-suite injection (F22)?

Before the F22 closure, every Sign-path primitive hardcoded
`blake3.New()`. This made it structurally impossible to switch the
production hash suite from Corona-BLAKE3 to Corona-SHA3 (cSHAKE256 /
KMAC256 / TupleHash256 per FIPS 202 + SP 800-185) without modifying
every primitive's source.

F22 (`CHANGELOG.md`) plumbed `hash.HashSuite` through every
primitive as a first-argument parameter, with `nil` resolving to the
production default at call time. This enables:

- Production deployments use Corona-SHA3 (NIST-aligned hash suite).
- KAT regeneration for the legacy Corona-BLAKE3 path remains
  available via `hash.NewCoronaBLAKE3()` for cross-port byte checks.
- New suites (e.g., a hypothetical Corona-Ascon) can be added
  without touching the primitives.

The architectural pattern is: **every cryptographic primitive takes
the suite as its first argument**; the suite is a value, not a
package-level global or build flag.

## §7 Why Corona-SHA3 (not Corona-BLAKE3) in production?

NIST alignment. The MPTC submission profile uses only FIPS 202 + SP
800-185 hash functions. BLAKE3 is fast and excellent, but it is
NOT a NIST standard at submission time. For the NIST MPTC submission
package, the normative hash suite is Corona-SHA3; BLAKE3 is retained
only for cross-port byte-check via `hash.NewCoronaBLAKE3()`.

The customization-string registry in `hash/sp800_185.go`:
- `CORONA-HC-v1` — challenge hash (`H_c`)
- `CORONA-HU-v1` — uniform hash (`H_u`)
- `CORONA-PRF-v1` — per-pair PRF seed derivation
- `CORONA-MAC-v1` — per-pair KMAC key derivation
- `CORONA-DKG-v1` — DKG commitment derivation
- `CORONA-RESHARE-v1` — resharing transcript hash

Adding a new customization string requires regenerating ALL KAT
vectors and updating `SPEC.md` §13.

## §8 Why no mechanized refinement proof at this submission?

Honesty: Corona's underlying construction (Boschini et al.
2024/1113) is published academic prior art that has no NIST standard
target. There is no FIPS spec to refine against. Mechanizing the
construction itself (without a separately-specified refinement
target) is a multi-month research project comparable to the
Barbosa-Barthe-Dupressoir Dilithium mechanization for FIPS 204.

Pulsar can refine against FIPS 204 because FIPS 204 IS the NIST
standard for ML-DSA. Corona has no analogous target.

Roadmap v0.7.0 begins the EasyCrypt theory shell for the
construction-level interchangeability claim and the Lean 4 / Mathlib
mechanization of the Lagrange-aggregation identity over `R_q`.
Roadmap v0.8.0 adds external cryptographic audit. At submission
scaffolding (v0.5.0), the correctness evidence is code review + KAT
+ Boschini et al. analysis.

## §9 Why `R_q^M` and not flat `R_q`?

Module-of-rings structure (`R_q^M` for `M = 8`) gives a security-
size trade-off: the per-coefficient cost is amortized across module
slots, the security analysis decomposes per-slot, and the wire size
scales linearly in `M` rather than quadratically. This is the
standard pattern in lattice-based signatures (FIPS 204 uses
`R_q^k × R_q^l` for the same reason).

The single-slot choice (flat `R_q`) was rejected because the
security margin would be marginal and the wire-size win would not
compensate for the loss of the per-slot security decomposition.

## §10 Why ML-KEM-768 hybrid (recommended) for per-pair KEX?

Per-pair encrypted-share exchange in `dkg2/` and `reshare/` uses an
authenticated KEX. Production deployments are recommended to use
**ML-KEM-768 hybrid** (X25519 ⊕ ML-KEM-768 via the X-Wing combiner
or equivalent) to provide both classical and post-quantum security.

The KEM choice is consumer-side (Corona does not impose ML-KEM-768
specifically) — the spec only requires "authenticated KEX." The
recommendation reflects Lux's deployment posture for Quasar
consensus.

## §11 Why the QUASAR-CORONA-* domain-separation prefix family?

Domain separation prevents cross-context attack composition. Every
signature produced under any Quasar lane carries a distinct
version-tagged prefix. The `QUASAR-CORONA-*` family separates
Corona's signing messages from Pulsar's signing messages and from
classical BLS aggregate certs:

- `QUASAR-CORONA-BUNDLE-v1` — Corona pulse over a Quasar bundle
- `QUASAR-CORONA-SIGN1-v1` — Corona signing Round 1 commit
- `QUASAR-CORONA-SIGN2-v1` — Corona signing Round 2 response
- `QUASAR-CORONA-COMBINE-v1` — Corona finalize transcript
- `QUASAR-CORONA-REFRESH-v1` — Refresh activation cert
- `QUASAR-CORONA-RESHARE-v1` — Reshare activation cert
- `QUASAR-CORONA-ACTIVATE-v1` — Generic activation cert
- `QUASAR-CORONA-REANCHOR-v1` — Reanchor authorization

Reusing a prefix across two distinct message classes would create a
domain-confusion attack surface. The convention: every NEW class of
signed message gets a NEW version-tagged prefix. NEVER reuse.

## §12 Why patch-bump-only versioning?

Per `CLAUDE.md` and `CHANGELOG.md`: patch bumps only
(`v0.4.x → v0.4.y`); minor/major bumps require explicit approval.
This forces every change to be evaluated against the established
KAT vectors and cross-runtime byte-equality manifest. A minor bump
implies wire-format changes that break downstream consumers'
go.mod pins and require coordinated validator-set rollover; that is
a deliberate, audited action, not a default.

The v0.5.0 bump for the submission-package scaffolding is the
documented exception: it adds documentation only, no code changes,
no KAT changes.

## §13 Why constant-time per-slot accumulation (not early return) in dkg2?

Findings 5/6 of upstream `RED-DKG-REVIEW.md`. The naive
implementation of Pedersen commit verification iterates over module
slots and returns false on the first mismatch. This leaks the
first-diverging slot index to a network observer measuring the
recipient's response time — which is a real timing oracle in
synchronous Quasar consensus.

`dkg2/dkg2.go:VerifyShareAgainstCommits` uses the
`eq &= subtle.ConstantTimeCompare(lhs, rhs)` accumulation pattern
across all `M` slots with NO early return. The recipient's
response time depends only on `M` (public structural metadata),
not on which slot first diverged.

This is documented in `CONSTANT-TIME-REVIEW.md` §2 and is a
patentable contribution (claim group D in
`docs/mptc/patent-claims.md`).

---

**Document metadata**

- Name: `docs/mptc/design-decisions.md`
- Version: v0.1 (initial submission-package scaffolding)
- Date: 2026-05-18
