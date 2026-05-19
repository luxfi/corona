# PROOF-CLAIMS — Corona (HONEST framing)

> **What this submission proves, and — critically — what it does NOT.**
> Companion to `TRUSTED-COMPUTING-BASE.md` (TCB) and `SUBMISSION.md`
> (cover sheet).
>
> Read this before reading the Corona code. The framing matters as
> much as the implementation.

## §1 The narrow claim Corona makes at this submission

The strongest precise statement supported by Corona v0.4.1:

> **Construction-level interchangeability (Class N1).** Every
> signature byte string produced by the Corona threshold combine
> procedure (`threshold.Combine` / `sign.LocalSign` aggregation flow)
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

### §3.1 NOT proved: mechanized refinement against any spec

Corona ships **no EasyCrypt theories, no Lean theorems, no Jasmin
sources**. Pulsar (the M-LWE sibling at `~/work/lux/pulsar/`) ships
13/13 EasyCrypt files compiling clean with 0/0 admits, 5/5 Lean ↔ EC
bridges, and 3/3 jasmin-ct blocking gates on the threshold layer.
**Corona does NOT.**

**Why**: R-LWE threshold signing has no NIST standard target. The
Boschini et al. ePrint 2024/1113 construction IS the spec. Mechanizing
the construction itself (without a separately-specified refinement
target) is a multi-month research project. Pulsar can refine against
FIPS 204; Corona has no analogous target.

**What this means in practice**: a NIST reviewer should NOT expect
to find a `Corona_N1.ec` file with a `corona_n1_byte_equality_extracted`
lemma analogous to Pulsar's. The trust base for Corona's correctness
reduces to:

- The Boschini et al. ePrint 2024/1113 academic analysis.
- The Go reference implementation review.
- The KAT cross-validation (Go ↔ C++ byte-equality).
- The constant-time static audit in `CONSTANT-TIME-REVIEW.md`.
- The fuzz harness coverage (operational at submission scaffolding;
  submission-grade budgets are roadmap).

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

### §3.7 NOT proved: external Lean theorems or EC bridges

Corona has NO Lean-bridged algebraic axioms (unlike Pulsar, which
has 5: `lagrange_inverse_eval`, `threshold_partial_response_identity`,
`add_share_zeroR`, `reconstruct_linear`, `shamir_correct`). The
Lagrange-aggregation identity over `R_q` that Corona uses in
combine is implemented by inspection of the Boschini et al. paper;
mechanizing it (either porting Mathlib's polynomial-Lagrange to EC
or building a Lean ↔ EC bridge analogous to Pulsar's
`proofs/lean-easycrypt-bridge.md`) is roadmap item v0.7.0.

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
test**, NOT machine-checked. Compare to Pulsar's refinement chain
(machine-checked at every step via EasyCrypt 13/13 + Lean bridges
5/5 + Jasmin-CT 3/3).

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

| Milestone | Target version |
|---|---|
| Single-document `spec/corona.tex` consolidating LaTeX | v0.6.0 |
| EasyCrypt theory shell for the construction-level interchangeability claim | v0.7.0 |
| Lean 4 / Mathlib mechanization of Lagrange-aggregation over `R_q` | v0.7.0 |
| dudect-style statistical CT validation harness | v0.8.0 |
| External cryptographic audit (engaged lab) | v0.8.0 |
| Parameter-set worksheet (lattice-estimator concrete bounds) | v0.6.0 |

The closure path is real but long. The honest framing at this
submission: production-hardened implementation of a published
academic construction, with production lifecycle additions, NOT
machine-checked refinement of a NIST standard.

---

**Document metadata**

- Name: `PROOF-CLAIMS.md`
- Version: v0.1 (initial submission-package scaffolding)
- Date: 2026-05-18
