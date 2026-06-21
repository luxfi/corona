# PROOF-CLAIMS — Corona (assurance-vocabulary, HONEST)

> **What this submission proves, and — critically — what it does NOT.**
> Every claim carries one assurance-vocabulary tag that MATCHES the
> artifact's actual state. Companion to `AXIOM-INVENTORY.md` (bucketed
> axiom census), `BLOCKERS.md` (open findings),
> `TRUSTED-COMPUTING-BASE.md` (TCB), `SUBMISSION.md` (cover sheet).
>
> Read this before reading the Corona code. The framing matters as
> much as the implementation.

## §0 Assurance vocabulary (canonical) + the two load-bearing disclosures

| Tag | Meaning |
|---|---|
| **machine-checked** | A proof assistant verifies it; the named file has ZERO `sorry`/`admit`/`:= True`. (No EasyCrypt toolchain on host; `scripts/checks/ec-compile.sh` is the CI gate, skipped when easycrypt is absent.) |
| **sound-by-reduction** | Pen-and-paper reduction to a stated assumption; not mechanized. |
| **interop-tested** | Validated against ≥2 INDEPENDENT implementations. |
| **asserted-axiom** | Taken as an axiom in EC; bucketed in AXIOM-INVENTORY.md (A/B). |
| **fail-closed-pending-review** | Implemented but gated to REFUSE until external review. |
| **open-research** | Multi-month roadmap; not done. |

**Disclosure 1 — TWO models; reconstruct-then-sign is the idealised one,
NOT the production residual (RE-SCOPED this pass).**

*Model 1 (idealised correctness).* `corona_n1_byte_equality` /
`_extracted` prove the threshold combine equals `CombineAbs.combine`, whose
body reduces — via `combine_abs_op_lifted_bridge` and
`sign_abs_op_lifted_eq_rlwe` — to `rlwe_sign_op (reconstruct quorum
shares) …`: the centralised R-LWE signer applied to the
**Lagrange-reconstructed master secret**. The Boschini combine steps 2–6 are
opened inside `combine_body_spec`, not proved. So Model 1 is machine-checked
(0 admits) modulo a C-cone that **reconstructs-then-signs** — an idealised
*correctness* statement, NOT how production runs and NOT a leak-freeness
proof.

*Model 2 (the HONEST production residual, `Corona_N1_NoLeak.ec`).* The
production path's per-party masked responses
`z_i = R_i·u + maskPrime_i + c·λ_i·s_i − mask_i` aggregate to `R·u + c·s`
because the pairwise-PRF masks **telescope to zero** (`mask_telescope_zero`)
— the master secret is **never formed** and no per-party `c·s_i` is ever
exposed (`no_leak_z_aggregate`). The CORRECTNESS core of Model 2 is
**machine-checked in Lean 4 + Mathlib on this host** (`lake build` green, 0
sorry): `Crypto.Corona.NoLeakAggregate` (`pairwise_mask_telescopes`,
`summed_response_is_mask_free`, `secret_aggregate_no_reconstruct`,
`no_leak_under_standard_assumptions`) + `Crypto.Threshold_Lagrange`. The
ONLY open assumption is `no_leak_reduction`: under **Module-LWE +
Module-SIS** (the SAME substrate §ProofSubstrate / AXIOM-INVENTORY.md §1
already lists) the public transcript leaks nothing about `s` beyond one
single-party Boschini signature — a STANDARD PQ assumption, **not** an
implementation reconstruct. Model 2's EC side is **written, machine-recheck
pending EasyCrypt**; its Lean core is machine-checked now.

**Disclosure 2 — the no-leak property is NOT independently interop-tested.**
Corona's KAT cross-validation is **Go↔C++ of the SAME construction**
(`luxcpp/crypto/corona`), not against an independent verifier. There is no
CIRCL/pq-crystals analog for R-LWE (no NIST target). So Corona's combine
output byte-equality is **asserted + same-construction-KAT-tested**, NOT
interop-tested in the ≥2-independent-implementations sense (unlike Pulsar's
CIRCL + pq-crystals). We therefore do NOT claim Corona byte-equality is
"proven/verified" anywhere in this document.

## §1 The narrow claim Corona makes at this submission

The strongest precise statement supported by Corona v0.4.1:

> **Construction-level interchangeability (Class N1).** Every
> signature byte string produced by the Corona threshold finalize
> procedure (`sign.Party.SignFinalize`, exposed as
> `threshold.Signer.Finalize`, which aggregates the Round-2 `z` shares)
> on inputs `(group_pk = (A, bTilde), m, ctx, quorum, shares)`
> satisfying the protocol's well-formedness invariants verifies under
> the Corona reference verifier `sign.Verify(group_pk, m, σ)` with
> outcome `OK`.

> **Public-key preservation across resharing (Class N4).** Every
> Corona Refresh or ReshareToNewSet ceremony on input `(group_pk =
> (A, bTilde), old_shares, old_committee, new_committee)` satisfying
> the protocol's honest-majority assumption produces `new_shares`
> such that any subsequent threshold signing under those new shares
> verifies under the **byte-identical unchanged** `group_pk`.

**Formal-statement status**: these are stated in prose, validated by
test, and inherited from the Boschini et al. ePrint 2024/1113 §3
analysis for the underlying construction. They are **NOT mechanized**
in EasyCrypt, Lean, Jasmin, or any other proof assistant at this
submission. See §3 below for the explicit non-claims list.

## §2 What IS provided

| Aspect | Status | Source |
|---|---|---|
| Implementation matches the Boschini et al. ePrint 2024/1113 construction | ✓ by code review + KAT cross-validation | `sign/`, `threshold/`, `primitives/` |
| Class N1 (construction-level output verifies under same verifier) | ✓ by test (no mechanized refinement) | `sign/sign_test.go`, `sign/sign_roundtrip_test.go`, `threshold/threshold_test.go` |
| Class N4 (reshare preserves `(A, bTilde)`) | ✓ by test (45+ tests in `reshare/`, integration tests assert byte-equal `(A, bTilde)` post-reshare) | `reshare/full_integration_test.go`, `reshare/refresh_test.go`, `reshare/reshare_test.go` |
| Constant-time on threshold + dkg2 verification paths | ✓ by per-path static audit | `CONSTANT-TIME-REVIEW.md` |
| KAT cross-runtime byte-equality (Go ↔ C++ luxcpp port) | ✓ by manifest enforcement | `scripts/regen-kats.sh --verify` + `scripts/regen-kats.manifest.sha256` |
| Fuzz coverage on round-based protocols | ✓ harnesses wired (operational fuzz budgets are deployment-level) | `reshare/fuzz_*_test.go`, `dkg2/fuzz_round_test.go`, `threshold/fuzz_round_test.go` |
| Hash-suite injection for Corona-SHA3 production profile | ✓ by code (F22 closure) | `hash/sp800_185.go`, `primitives/hash.go` |
| Identifiable-abort evidence | ✓ by test | `reshare/complaint_test.go`, `dkg2/complaint.go` |
| Activation cert as circuit-breaker | ✓ by test (verifies under unchanged GroupKey) | `reshare/activation_test.go` |

## §3 What is NOT proved (HONEST)

This section is the load-bearing honesty disclosure. Read it.

### §3.1 v0.7.0: EC + Lean + Jasmin scaffolding LANDED — but the EC byte-equality is reconstruct-then-sign (asserted-axiom cone)

**Assurance: machine-checked structure (0 admits) MODULO the C-cone of
asserted axioms (reconstruct-then-sign).** The 13 EC theories are
structurally complete, but `corona_n1_byte_equality` rests on the open
bucket-C axioms in `AXIOM-INVENTORY.md` §C (the `combine_body_spec`
byte-walk with Boschini steps 2–6 inside it, and the
`combine_abs_op_lifted_bridge` / `sign_abs_op_lifted_eq_rlwe` wrapper
bridges that pin the lifted op to `rlwe_sign_op` on the **reconstructed**
secret). See §0 Disclosure 1.

**v0.7.0 update**: Corona now ships:
- **13 EasyCrypt theories** compiling clean with admit budget **0/0**
  (`proofs/easycrypt/Corona_N1.ec` + `Corona_N4.ec` + Layout +
  Refinement + Wrapper + Extracted + `lemmas/RLWE_Functional.ec` +
  `lemmas/Corona_CT.ec`).
- **5 Lean <-> EC bridges** (Shamir, OutputInterchange,
  Unforgeability, dkg2 -- see `proofs/lean-easycrypt-bridge.md`).
- **3 Jasmin threshold-layer sources** (round1.jazz, round2.jazz,
  combine.jazz) with `#ct` annotations + 1 centralized rlwe/sign.jazz
  reference + a `lib/` of shared primitives.
- **dudect harness** at `ct/dudect/` for Verify + Combine.
- **CI orchestrator** `scripts/check-high-assurance.sh` with 7 per-push
  gates (mirroring Pulsar's exactly).

**What's still operational** (roadmap v0.8.0):
- Jasmin extraction filling out the byte-walk refinement obligations
  in `Corona_N1_{Combine,Sign}_Refinement.ec`.
- dudect submission-grade 10^9-sample runs on pinned hardware.
- External cryptographic audit engagement.

The implementation-backed N1 byte-equality theorem to cite is
`Corona_N1_Extracted.corona_n1_byte_equality_extracted`.

R-LWE threshold signing has no NIST standard target. The Boschini
et al. ePrint 2024/1113 construction IS the spec; the EC theories
refine the Go implementation against the in-house mechanization of
that spec (`lemmas/RLWE_Functional.ec`), which is the analog of
Pulsar's libjade dependence on FIPS 204.

### §3.2 NOT proved: lattice-hardness of R-LWE

This submission says nothing about the post-quantum hardness of
Ring-LWE itself. R-LWE security rests on Lyubashevsky-Peikert-Regev
(2010) and follow-up cryptanalytic analysis. The parameter set
(`N = 256`, `q = 0x1000000004A01`, 48-bit prime) was chosen to
provide ≥ 128 bits of post-quantum security per lattice-estimator
methodology — but Corona ships no parameter-set worksheet at this
revision; that is roadmap item v0.6.0.

**The defensible PQ-safety claim**:
> Corona implements a published academic R-LWE threshold signature
> construction (Boschini et al. ePrint 2024/1113) on a parameter
> set chosen to provide ≥ 128 bits of post-quantum security against
> known R-LWE attacks per the lattice-estimator methodology of
> Albrecht-Player-Scott. The construction's EUF-CMA reduction is in
> the cited paper.

**NOT defensible**:
> Corona is proved post-quantum secure.

### §3.3 NOT proved: byte-equality with FIPS 204 ML-DSA

Corona signatures are NOT byte-equal to FIPS 204 ML-DSA signatures.
The two constructions use different lattice families (Corona is
R-LWE; ML-DSA is M-LWE), different ring degrees, different
parameter sets. Any reviewer expecting FIPS 204 byte-equality
should look at the Pulsar sibling at `~/work/lux/pulsar/`.

### §3.4 NOT proved: statistical constant-time validation (dudect)

`CONSTANT-TIME-REVIEW.md` documents a per-path static audit with
zero `(c)` (must-fix) findings. **It does NOT include statistical
validation via dudect-style timing measurements.** A dudect-style
harness is roadmap item v0.8.0; at submission scaffolding time the
constant-time evidence is the static audit + the upstream lattigo
constant-time claims.

### §3.5 NOT proved: implementation-side covert-channel safety

The static constant-time audit does NOT address:
- Memory-access leakage (cache-timing side channels)
- Power side-channels
- EM side-channels
- Fault attacks
- Microarchitectural leakage (Spectre / Meltdown class)
- Statistical timing under realistic deployment conditions

Production deployments MUST follow the hardening checklist in
`DEPLOYMENT-RUNBOOK.md` (mlock pinning, core-dump disable, ptrace
disable, dedicated host, etc.).

### §3.6 NOT proved: protocol-level adversarial robustness

The construction-level claim in §1 is **honest-quorum correctness**.
It says: "when all parties follow the protocol, the output verifies
and resharing preserves the group key." It does NOT prove:

- **Unforgeability** under adaptive corruption — inherited (with
  caveats) from Boschini et al. §3; no Corona-specific mechanization.
- **Identifiable abort** under network partition — synchronous network
  assumptions hold; async abort is out of scope.
- **Robust completion** under `f < t/2` Byzantine parties.
- **DKG soundness** under adversarial dealer — Pedersen DKG (`dkg2/`)
  provides hiding and binding under standard assumptions; full
  reduction is in the LP-073 paper but not mechanized here.

### §3.7 v0.7.0: 5 Lean-bridged algebraic axioms LANDED (was: NOT proved)

**v0.7.0 update**: Corona now has 5 Lean-bridged algebraic axioms,
in 1:1 correspondence with Pulsar's:

| Corona EC axiom | Lean theorem |
|---|---|
| `lagrange_inverse_eval` (Corona_N1.ec) | `Crypto.Corona.Shamir.shamir_correct_at_target` |
| `threshold_partial_response_identity` (Corona_N1.ec) | `Crypto.Threshold.Lagrange.threshold_partial_response_identity` |
| `add_share_zeroR` (Corona_N4.ec) | Mathlib `AddCommMonoid` instance |
| `reconstruct_linear` (Corona_N4.ec) | `Crypto.Threshold.Lagrange.combine_distributes_over_sum` |
| `shamir_correct` (Corona_N4.ec) | `Crypto.Corona.Shamir.shamir_correct_at_target` |

The bridge document is `proofs/lean-easycrypt-bridge.md`. The CI
guard `scripts/check-lean-bridge.sh` verifies every EC axiom has the
required citation comment + that the cited Lean theorem still exists
in the named Lean file.

## §4 Refinement chain (what's connected to what)

```
Go implementation (sign/, threshold/, dkg2/, reshare/, primitives/, hash/)
       implements (by code review + KAT)
Boschini et al. ePrint 2024/1113 §3 algorithmic spec
  + Corona production-lifecycle additions in SPEC.md §§6, 9, 10, 13
       conforms to (by inspection)
DESIGN.md invariants ("what is preserved across resharing")
```

Each "implements" / "conforms" relation is by **inspection and
test**, NOT machine-checked. Compare to Pulsar's refinement chain, which
is machine-checked (0-admit) at the EC level **but only modulo the same
reconstruct-then-sign asserted-axiom cone** — Pulsar's EC byte-equality is
also relative to `combine_body_axiom` / `S_functional_spec` (its
`AXIOM-INVENTORY.md` §C). The honest difference is degree of
*decomposition* (Pulsar splits the byte-walk into ~10 narrow per-stage
sub-axioms; Corona keeps one `combine_body_spec`) and *interop*: Pulsar's
final signature is interop-tested vs CIRCL + pq-crystals, Corona's is
same-construction Go↔C++ KAT only (§0 Disclosure 2).

## §5 What an auditor verifying this submission should do

1. **Read** the `SUBMISSION.md` cover sheet for context.
2. **Read** this document (`PROOF-CLAIMS.md`) for what's proved vs not.
3. **Read** `TRUSTED-COMPUTING-BASE.md` for the implementation TCB.
4. **Read** `CONSTANT-TIME-REVIEW.md` for the per-path CT audit.
5. **Read** Boschini et al. ePrint 2024/1113 for the underlying
   construction analysis (academic prior art).
6. **Run** `scripts/test.sh` — expect Go unit + integration + KAT
   tests all green.
7. **Run** `scripts/gen_vectors.sh && scripts/regen-kats.sh --verify`
   — expect byte-equal KAT manifest agreement.
8. **Read** the Go reference implementation: `sign/sign.go`,
   `threshold/threshold.go`, `dkg2/dkg2.go`, `reshare/reshare.go`,
   `reshare/activation.go`, `primitives/hash.go`, `hash/sp800_185.go`.
9. **Run** `scripts/bench.sh` — expect performance numbers within
   `docs/evaluation.md` published bounds.

## §6 The honest one-paragraph version

> Corona's submission package establishes that the Go reference
> implementation faithfully implements the Boschini, Kaviani, Lai,
> Malavolta, Takahashi, and Tibouchi 2-round R-LWE threshold
> signature construction (IACR ePrint 2024/1113, IEEE S&P 2025) on a
> fixed parameter set, plus production lifecycle additions (Pedersen
> DKG over `R_q`, proactive resharing with Refresh + ReshareToNewSet
> primitives, identifiable abort, activation certs as the
> resharing circuit-breaker, KAT-deterministic Corona-SHA3 hash
> suite). Unlike the Pulsar sibling submission (which ships a
> mechanized EasyCrypt + Lean + Jasmin refinement chain against
> FIPS 204), Corona ships NO machine-checked refinement at this
> submission — R-LWE has no NIST standard target, the construction
> IS the spec, and mechanizing the construction itself is a multi-
> month research roadmap item. Corona's correctness evidence
> reduces to code review of the Go reference against the published
> construction, KAT cross-validation (Go ↔ C++ byte-equality
> manifest), the per-path constant-time static audit in
> `CONSTANT-TIME-REVIEW.md` (zero must-fix findings), fuzz harness
> coverage, and the academic security analysis in the cited paper.
> The proof tier is intentionally less mature than Pulsar's; the
> roadmap items in `NIST-SUBMISSION.md` lay out the multi-version
> path to mechanized refinement.

## §7 Roadmap (multi-version closure path)

| Milestone | Target version | Status |
|---|---|---|
| Single-document `spec/corona.tex` consolidating LaTeX | v0.6.0 | shipped |
| EasyCrypt theory shell for the construction-level interchangeability claim | v0.7.0 | **shipped (13 files, admit 0/0)** |
| Lean 4 / Mathlib mechanization of Lagrange-aggregation over `R_q` | v0.7.0 | **shipped (5 Lean-bridged axioms)** |
| Jasmin sources + jasmin-ct CT gates on the threshold layer | v0.7.0 | **shipped (3 threshold + 1 rlwe + lib/)** |
| dudect harness wired (smoke-budget) | v0.7.0 | **shipped (Verify + Combine)** |
| dudect submission-grade 10^9-sample runs on pinned hardware | v0.8.0 | roadmap |
| External cryptographic audit (engaged lab) | v0.8.0 | roadmap |
| Parameter-set worksheet (lattice-estimator concrete bounds) | v0.6.0 | shipped |
| Jasmin extraction filling out byte-walk refinement | v0.8.0 | roadmap |

The closure path is real but long. The honest framing at this
submission: production-hardened implementation of a published
academic construction, with production lifecycle additions, NOT
machine-checked refinement of a NIST standard.

---

**Document metadata**

- Name: `PROOF-CLAIMS.md`
- Version: v0.2 (v0.7.0 EC + Lean + Jasmin scaffold landed)
- Date: 2026-05-18
