# TRUSTED-COMPUTING-BASE — Corona implementation TCB

> **What you must trust to rely on Corona's construction-level
> correctness claim.** Companion to `PROOF-CLAIMS.md` (proof scope)
> and `CONSTANT-TIME-REVIEW.md` (per-path CT audit).
>
> **HONESTY NOTE**: Corona's TCB is structurally simpler than Pulsar's
> because Corona ships NO mechanized refinement layer (no EasyCrypt,
> no Lean, no Jasmin). That removes those tools from the TCB but
> increases the trust placed in the Go reference implementation
> review, KAT cross-validation, and the academic Boschini et al.
> construction analysis. See `PROOF-CLAIMS.md` for the honest framing.

## §0 Layered trust bases

The Corona construction-level claim rests on three layered trust
bases:

1. **The academic construction** — Boschini, Kaviani, Lai, Malavolta,
   Takahashi, Tibouchi. *Practical two-round threshold signatures
   from learning with errors.* IACR ePrint 2024/1113, IEEE S&P 2025.
   This is the spec.
2. **The Go reference implementation** — `sign/`, `threshold/`,
   `dkg2/`, `reshare/`, `primitives/`, `hash/`. Reviewed by code
   inspection + KAT cross-validation + fuzz.
3. **The trusted-computing base (TCB) below the implementation** —
   this document.

If any element of the TCB is unsound, the implementation's correctness
is unsound regardless of how clean the code review was.

## §1 Implementation TCBs

### §1.1 Reference implementation (Go)

| Component | Trust | Mitigations |
|---|---|---|
| Corona Go reference (this repository) | Standard library correctness, `crypto/rand` randomness quality, lattigo NTT/Montgomery/Gaussian-sampler primitives | Reviewed by code inspection; KAT cross-validation Go ↔ C++ (luxcpp port); fuzz harnesses on round-based protocols |
| `github.com/luxfi/lattice/v7` (lattigo fork) | Upstream `tuneinsight/lattigo/v7` NTT, Montgomery reduction, discrete-Gaussian sampler. Documented constant-time per upstream README; relevant routines are byte-stable. | Version pinned in `go.mod`. The fork carries Lux-specific extensions for hash-suite injection but the cryptographic kernels are unchanged from upstream. |
| `github.com/luxfi/math/codec` | LP-107 Phase 4 wire codec. Validates `Vector[Poly]` frame before lattigo `ReadFrom`. | Version pinned in `go.mod`. |
| `golang.org/x/crypto/sha3` | cSHAKE256, KMAC256, TupleHash256 primitives (Go-stdlib-style). | Version pinned in `go.mod`. |
| `crypto/subtle` | Constant-time byte-blob compare. Standard library. | Standard library; bundled with the Go toolchain. |
| `github.com/zeebo/blake3` | Legacy BLAKE3 hash suite (cross-port byte-check only; NOT the normative production profile). | Version pinned in `go.mod`. Legacy use only. |

### §1.2 Production targets (out of scope for v0.2)

| Target | Status |
|---|---|
| Optimized Rust crate | TODO — not in this submission |
| C library + FFI | C++ port at `~/work/luxcpp/crypto/corona/` is the de-facto C-ABI; clean C wrapper TODO |
| WASM build | TODO |
| no_std embedded | TODO |

For each future target, an independent constant-time audit + KAT
cross-validation + binding-level fuzzing is required before
considering it "production." The construction-level correctness
claim does NOT automatically transfer to these targets — each
target's correctness must be re-verified.

## §2 Build TCBs

| Layer | What you trust | Reproducibility |
|---|---|---|
| **Go toolchain** | The Go compiler used to build the reference. Version pinned to `go 1.26.3` in `go.mod`. | Hard-pinned in `go.mod`; `go.sum` enforces module checksums. |
| **`scripts/build.sh`** | The build orchestrator's correctness — that it produces deterministic outputs from a fresh checkout. | CI runs the script on every commit. |
| **`scripts/test.sh`** | The test harness's correctness — that KAT vectors compare bit-by-bit, not just lex-equal. | Reviewed; uses `bytes.Equal` for byte-level KAT comparison. |
| **`scripts/gen_vectors.sh`** | Deterministic regeneration of KAT vectors. | Wraps `scripts/regen-kats.sh`; the manifest at `scripts/regen-kats.manifest.sha256` pins SHA-256 of every regenerated file. |
| **`scripts/regen-kats.sh --verify`** | Cross-runtime byte-equality enforcement (Go ↔ C++). | Manifest is regenerated and compared; diff = build bug. |

## §3 What the TCB does NOT include

Corona's TCB is **structurally simpler** than Pulsar's because Corona
ships no mechanized refinement layer. The following are NOT in the
Corona TCB:

- **EasyCrypt prover** (Pulsar trusts it; Corona has no EC theories)
- **Lean 4 + Mathlib** (Pulsar uses Lean-bridged algebraic axioms;
  Corona has none)
- **Jasmin verified compiler** (Pulsar's threshold layer is in Jasmin;
  Corona is pure Go)
- **OCaml runtime** (EC is OCaml; Corona has no EC)
- **jasmin-ct** (Corona's CT evidence is static per-path audit, not
  jasmin-ct analysis)

What IS in the Corona TCB but NOT in Pulsar's:

- **Greater dependence on Go reference review.** Pulsar can fall
  back to the EC refinement chain if a Go reviewer misses a bug;
  Corona's only line of defense is reviewer + KAT + fuzz.
- **Greater dependence on the academic Boschini et al. paper.**
  Pulsar's spec target (FIPS 204) is an extensively-cryptanalyzed
  NIST standard; Corona's spec target is a 2024 academic paper with
  less cryptanalytic surface area at this writing.

## §4 What the TCB does NOT cover

These are explicitly NOT part of the trust base for Corona's
construction-level correctness claim:

- **Specific operating system** (Linux, macOS, BSD, Windows) — the
  Go reference is OS-independent.
- **Specific CPU architecture** — Go compiles to amd64/arm64; both
  exercised in CI.
- **Network protocol stack** — Corona's transport is out of scope.
- **Storage layer** — how `sk` shares are stored at rest is out of
  scope. Production deployments use HSM-backed share material; see
  `DEPLOYMENT-RUNBOOK.md`.
- **Key management policies** — key lifecycle is application-level
  (governed by the consuming consensus layer, e.g. Quasar).
- **Application code calling Corona** — Corona's API contract is the
  trust boundary.

## §5 TCB risks and mitigations

### §5.1 Construction-soundness risk

| Risk | Mitigation |
|---|---|
| The Boschini et al. ePrint 2024/1113 EUF-CMA reduction has a latent bug | Construction has been published and reviewed by the cryptographic community via IEEE S&P 2025 + IACR ePrint discussion. Lux tracks cryptanalysis literature; any flaw would prompt a parameter-set re-tune and a new key-era. Patent-bump policy and `DESIGN.md` "Reanchor" capability allow operational response. |
| Corona's production lifecycle additions (Pedersen DKG, reshare, activation cert) have a latent bug | Per-path tests in `dkg2/`, `reshare/` (45+ tests including `full_integration_test.go`). Independent third-party audit is roadmap item v0.8.0. |

### §5.2 Implementation-correctness risk

| Risk | Mitigation |
|---|---|
| Go reference implementation diverges from the construction | KAT cross-validation Go ↔ C++ (`scripts/regen-kats.sh --verify`); the C++ port is independently implemented from the same spec by a different engineer. Divergence = test failure. |
| KAT vectors are subtly wrong | Deterministic generation from fixed seeds; `cross_runtime_oracle/` and `cross_runtime_verify/` enforce Go ↔ C++ byte-equality. Both implementations would have to be wrong in the same way to escape this check. |
| Hash-suite implementation bug (cSHAKE256 / KMAC256 / TupleHash256) | `golang.org/x/crypto/sha3` is a widely-used standard library implementation; bugs are rare and quickly patched. NIST SP 800-185 KAT verification in `hash/hash_test.go` (`TestKMAC256NISTVector`, `TestTupleHash256NISTVector`). |

### §5.3 Build / reproducibility risk

| Risk | Mitigation |
|---|---|
| `scripts/build.sh` produces non-deterministic output | The build is deterministic from fixed seeds; reproducible-build property is checked on CI. Drift triggers a CI failure. |
| Toolchain version drift between commits | `go.mod` pin + `go.sum` enforcement. |
| KAT manifest drift across runs | `scripts/regen-kats.manifest.sha256` is the gate; `--verify` mode compares manifest hashes. |

### §5.4 Side-channel risk

| Risk | Mitigation |
|---|---|
| Timing leakage on secret-dependent paths | Static per-path audit in `CONSTANT-TIME-REVIEW.md` — zero `(c)` (must-fix) findings; two `(b)` entries with documented mitigations (one closed in `dkg2/`; one in lens-specific paths off the Corona threshold path). |
| Statistical timing leakage (dudect-style) | Roadmap item v0.8.0. Not validated at this submission. |
| Memory-access / cache-timing leakage | Not addressed. Production deployments should use TEE attestation (SGX, SEV-SNP, TDX) per `DEPLOYMENT-RUNBOOK.md`. |

## §6 Independent verification protocol

To independently verify Corona's claims, a reviewer should:

1. Clone the repo at the submission tag.
2. `scripts/build.sh` — expect deterministic output.
3. `scripts/test.sh` — expect KAT + integration + unit tests all green.
4. `scripts/gen_vectors.sh && scripts/regen-kats.sh --verify` — expect
   byte-equal KAT manifest agreement.
5. `scripts/bench.sh` — expect performance within `docs/evaluation.md`
   published bounds.
6. Read the Go reference implementation:
   - `sign/sign.go` — single-party + threshold signing kernel
   - `threshold/threshold.go` — threshold orchestration
   - `dkg2/dkg2.go` — Pedersen DKG over `R_q`
   - `reshare/reshare.go` + `reshare/activation.go` — proactive
     resharing + activation cert
   - `primitives/hash.go` + `hash/sp800_185.go` — Corona-SHA3 hash
     suite
7. Cross-reference with Boschini et al. ePrint 2024/1113 §3 for the
   2-round signing construction.
8. Cross-reference with `papers/lp-073-pulsar/` for the production
   lifecycle additions (Pedersen DKG, resharing).

If all 8 steps pass, the trust base reduces to the TCB enumerated
in this document.

## §7 What this means for downstream consumers

For a downstream consumer (e.g., a Quasar consensus chain
incorporating Corona):

- **The construction-level claim is conditional on the TCB.** If
  you change the Go toolchain, port to a different runtime, or
  modify the hash suite, the claim's transferable guarantees
  attenuate.
- **For FIPS 140-3 module validation**, Corona is NOT a candidate
  — R-LWE threshold has no NIST standard, so no FIPS 140-3 module
  can claim FIPS 204-style algorithm validation for it. For
  FIPS-validation pathways, use Pulsar (M-LWE / FIPS 204) instead.
- **For NIST MPTC review**, Corona's role is the algorithm-level
  reference + production lifecycle artifacts; module packaging +
  external audit are downstream.
- **For threshold signing in a Quasar deployment**, Corona is the
  R-LWE kernel; the consuming consensus layer is responsible for
  the chain-of-custody and validator-rotation orchestration (the
  LSS adapter at `~/work/lux/threshold/protocols/lss/lss_pulsar.go`
  is the canonical orchestrator).

## §8 Honest comparison to Pulsar's TCB

| TCB element | Pulsar | Corona |
|---|---|---|
| EasyCrypt prover | YES (foundation of refinement proof) | NO (no EC theories) |
| Lean 4 + Mathlib | YES (5 Lean-bridged axioms) | NO |
| Jasmin verified compiler | YES (threshold layer in Jasmin) | NO (pure Go) |
| OCaml runtime | YES (EC is OCaml) | NO |
| Go toolchain | YES (Go reference) | YES (Go reference; primary) |
| lattigo / `luxfi/lattice/v7` | NO (Jasmin path) | YES (R-LWE primitives) |
| `crypto/subtle` | YES (Go reference path) | YES (primary CT helper) |
| `golang.org/x/crypto/sha3` | YES | YES |
| Academic construction paper | FIPS 204 (NIST standard) | Boschini et al. ePrint 2024/1113 (2024 academic) |
| Third-party FIPS-validated verifier | YES (BoringSSL FIPS / AWS-LC / OpenSSL 3.0) | NO (none exists for R-LWE threshold) |

**Net effect**: Corona's TCB is smaller (fewer proof-tool
dependencies) but the trust per-component is higher (no fall-back
to a mechanized refinement chain if a Go reviewer misses a bug).

---

**Document metadata**

- Name: `TRUSTED-COMPUTING-BASE.md`
- Version: v0.1 (initial submission-package scaffolding)
- Date: 2026-05-18
- Go toolchain pin: `go 1.26.3` (per `go.mod`)
- `luxfi/lattice/v7` pin: `v7.1.0` (per `go.mod`)
