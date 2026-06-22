# Finding registry — luxfi/corona

**Status: OPEN items present (see `## Open`).** Corona's single-party /
N4 reshare / code-review-against-Boschini claims are at the disclosed
v0.7.0/v0.8.0-roadmap tier; the EasyCrypt byte-equality proof rests on an
OPEN reconstruct-then-sign axiom cone, the constant-time evidence is a
static audit (dudect-submission-grade pending), and there is no independent
interop verifier for the R-LWE construction. None of these is hidden — they
are the honest proof-tier of a published-construction implementation. See
`PROOF-CLAIMS.md` §0 and `AXIOM-INVENTORY.md` §C.

This file is the finding registry. New findings open under `## Open`; on
fix they move to `## Closed` with commit + tag.

## Open

### CORONA-EC-RECON-MODEL (HIGH — proof-scope disclosure; RE-SCOPED this pass)

**Status: OPEN, but RE-SCOPED — reconstruct-then-sign is no longer the
load-bearing production residual.** Two distinct models now exist:

**Model 1 — idealised correctness (reconstruct-then-sign).** The EC
`corona_n1_byte_equality` / `_extracted` is machine-checked structurally (0
admits) **relative to** the bucket-C-idealised axioms:
- `combine_body_spec` (the atomic Jasmin byte-walk) — the Boschini combine
  steps 2–6 are INSIDE it, unproved.
- `combine_abs_op_lifted_bridge` + `sign_abs_op_lifted_eq_rlwe` — the
  wrapper bridges pinning the lifted op to
  `rlwe_sign_op (reconstruct quorum shares) …`, i.e. the centralised R-LWE
  signer on the **Lagrange-reconstructed master secret**.
- `combine_body_axiom` / `S_functional_spec` — the section-local contracts.

So Model 1 **reconstructs the master key and signs with it** — an idealised
*correctness* statement, intentionally NOT the production instantiation.

**Model 2 — the production no-leak residual (added this pass).**
`proofs/easycrypt/Corona_N1_NoLeak.ec` states the production path the way it
runs: the per-party masked responses
`z_i = R_i·u + maskPrime_i + c·λ_i·s_i − mask_i` aggregate to `R·u + c·s`
because the pairwise-PRF masks **telescope to zero** (`mask_telescope_zero`:
`Σ_i maskPrime_i = Σ_i mask_i`, the same double sum reindexed) — so the
master secret is **never formed** and no per-party `c·s_i` is ever in the
clear (`no_leak_z_aggregate`). The ONLY open assumption is
`no_leak_reduction`: under **Module-LWE + Module-SIS** the public transcript
leaks nothing about `s` beyond one single-party Boschini signature. That is
a STANDARD PQ assumption — the same substrate `AXIOM-INVENTORY.md` §1
already lists — **not** an implementation reconstruct.

**What is machine-checked NOW (this host, `lake build` green, 0 sorry):**
the CORRECTNESS core of Model 2 — `Crypto.Corona.NoLeakAggregate`
(`pairwise_mask_telescopes`, `summed_response_is_mask_free`,
`secret_aggregate_no_reconstruct`, `no_leak_under_standard_assumptions`) +
`Crypto.Threshold_Lagrange`. The EC side of Model 2 (`Corona_N1_NoLeak.ec`)
**machine-checks on this host** via `easycrypt compile` (opam switch `proofs`:
easycrypt + why3 + alt-ergo, z3 solver); the framework gate
`checks/ec-machine-check.sh` runs it on every invocation (corona: 14/14).

**Combine wrapper — the share-typed bridge is now DISCHARGED (residual
shrunk to a public-commitment equality).** `combine_abs_op_lifted` (the
share-typed lifted combine op) is now a **concrete threshold definition** —
the no-leak assembly `c = kmac_mu_w mu w_pub`; `z = lagrange_aggregate_
responses` of `per_party_partial_response`; `Delta = make_delta_of_w w_pub z`
— **not** an opaque op and **not** named as `rlwe_sign_op(reconstruct …)`.
The former axiom **`combine_abs_op_lifted_eq_rlwe`** (AXIOM-INVENTORY C11) is
now a **PROVEN LEMMA** on honest, well-formed quorums (uniq/size/degree/
sharing — exactly `wrapper_combine_refines_abs`'s preconditions):
- **z-LEG** (the load-bearing leg; the secret enters only as the public `z`'s
  `c*s` summand): discharged through the **machine-checked keystone**
  `Corona_N1_NoLeak.no_leak_z_aggregate` (= Lean
  `threshold_partial_response_identity`). Verified load-bearing — deleting the
  keystone rewrite makes the proof fail (`cannot close goals`). The master
  secret is never reconstructed.
- **c-LEG + Delta-LEG** (public): discharged through the single narrow PUBLIC
  residual **`threshold_public_commitment_eq_central`** (C11′) — the
  threshold-assembled public Fiat-Shamir commitment `w = A*y` (mask-summed, no
  `c*s`) equals the central `central_w`. Also verified load-bearing.
So `wrapper_combine_refines_abs` is now **machine-checked NOT conditional on
any reconstruct-then-sign axiom** — it rests only on the public-commitment
residual C11′ and the unchanged B-bucket codec bridges.

**What remains open (honest).** The residual is **narrowed, not eliminated**:
- **C11′ `threshold_public_commitment_eq_central`** — PUBLIC-ONLY (commitment
  `w = A*y`, no secret). This EC abstraction has no commitment-aggregate op
  (unlike the z-leg's `lagrange_aggregate_responses`), so the `w`-agreement
  stays a disclosed-open axiom. v0.8.0 discharge: a commitment-aggregate op +
  Lean bridge for the `A*y` mask-sum identity (the commitment analog of the
  already-machine-checked z-leg keystone).
- **C5 `combine_abs_op_lifted_bridge`** (lifted op ↔ byte-level
  `combine_abs_op`) — still a B/open codec bridge: `combine_abs_op` (the
  Jasmin byte-level op) remains OPAQUE. The byte-walk roadmap below targets
  THIS bridge (the wire/encoding layer), now that the share-level algebra is a
  lemma. Make both sides real definitions and prove decomposed (no magical
  equality):
  1. `Corona_N1_Encoding.ec` — `decode(encode(x)) = Some x` + canonical
     uniqueness + malformed rejection (B if codecs stay opaque, KAT/fuzz).
  2. `Corona_N1_Reconstruct.ec` — Lagrange/Shamir reconstruction correctness
     (A-class, already machine-checked in `Crypto.Corona.Shamir` /
     `Crypto.Threshold_Lagrange`).
  3. `Corona_N1_CombineSpec.ec` — the per-component (z / challenge / hint)
     reference meaning, reusing `combine_abs_op_lifted`'s now-concrete legs +
     `mask_telescope_zero`.
  4. `Corona_N1_CombineBridge.ec` — define `combine_abs_op` as the executable
     `decode → validate → combine_abs_op_lifted → encode` model (NOT as the
     answer), then prove `combine_abs_op(encoded) = combine_abs_op_lifted(args)`
     by rewrite chain.
  Only if `combine_abs_op` cannot be given an executable model does C5 stay a
  B/open implementation-spec bridge (tests/review), never a closed theorem.

Remaining OPEN:

- The production no-leak path's correctness is ALSO established by code
  review + cross-runtime KAT (Go↔C++); there is no independent R-LWE
  verifier (CORONA-NO-INDEP-VERIFIER — by design, no NIST target).
- `no_leak_reduction`'s full simulation-soundness proof (the v0.8.0
  EC/paper artifact) is not written; disclosed as a Module-LWE/MSIS reduction.
- Model 1's C-idealised cone closure is still the Jasmin byte-walk (v0.8.0)
  — but Model 1 is now explicitly *not* the safety-relevant residual.

**Resolution criteria:**
- [x] A separate (non-reconstruct) model of the PRODUCTION no-leak path is
      written, with its CORRECTNESS core machine-checked (Lean, this host)
      and its residual stated as a STANDARD Module-LWE/MSIS reduction
      (`Corona_N1_NoLeak.ec` + `Crypto.Corona.NoLeakAggregate`).
- [x] `Corona_N1_NoLeak.ec` machine-checks via `easycrypt compile` on the host
      (gate `checks/ec-machine-check.sh`; corona 14/14 theories compile).
- [ ] `no_leak_reduction` discharged to a full M-LWE/M-SIS simulation proof
      (v0.8.0), OR accepted by external review as a standard reduction.
- [x] `combine_abs_op_lifted_eq_rlwe` (C11) **DISCHARGED → LEMMA**:
      `combine_abs_op_lifted` made concrete (the no-leak threshold assembly);
      z-leg via the machine-checked keystone `no_leak_z_aggregate`, c/Delta-leg
      via the narrow PUBLIC residual `threshold_public_commitment_eq_central`
      (C11′). `wrapper_combine_refines_abs` is now machine-checked NOT
      conditional on any reconstruct-then-sign axiom. (Verified load-bearing:
      removing either the keystone or the commitment rewrite fails the proof.)
- [ ] C11′ `threshold_public_commitment_eq_central` (the residual public-`w`
      equality) discharged by a commitment-aggregate op + Lean `A*y` mask-sum
      bridge (the commitment analog of the z-leg keystone), AND the byte-level
      `combine_abs_op` (C5) given an executable model via the byte-walk
      decomposition above (Encoding/Reconstruct/CombineSpec/CombineBridge).
- [ ] Jasmin byte-walk lands ⇒ Model 1's C-idealised axioms become lemmas
      (correctness nicety).
- [ ] **External cryptographic review** (shared gate with CORONA-CT-PENDING
      and CORONA-NO-INDEP-VERIFIER) signs off that (a) Model 2's
      standard-reduction residual is the correct production posture and (b)
      Model 1 is an acceptable correctness idealisation.

### CORONA-CT-PENDING (MEDIUM — constant-time evidence)

**Status: OPEN.** Constant-time evidence for the threshold + DKG paths is a
per-path **static audit** (`CONSTANT-TIME-REVIEW.md`, zero must-fix
findings) plus the upstream lattigo CT claims. The EC `declare axiom`s
`sign_round1_constant_time` / `sign_round2_constant_time`
(`lemmas/Corona_CT.ec`, bucket C9/C10) are CT **contracts**, NOT
certificates — a timing property cannot be certified by an EC axiom or a
name grep (`proof-by-rename.sh` exists to catch that anti-pattern). The
dudect harness (`ct/dudect/`) is wired at smoke-budget.

**Resolution criteria:**
- [ ] `jasminc -checkCT` discharges the CT contracts on the extracted
      threshold layer (production target v0.8.0).
- [ ] dudect submission-grade 10⁹-sample run on pinned hardware.
- [ ] External review of the CT posture (shared external-review gate).

### CORONA-NO-INDEP-VERIFIER (MEDIUM — interop disclosure)

**Status: OPEN by design (no NIST target for R-LWE).** Corona's signature
byte-equality is cross-validated only **Go↔C++ of the SAME construction**
(`luxcpp/crypto/corona` via `scripts/regen-kats.sh --verify`), NOT against
an independent verifier. Unlike Pulsar (CIRCL + pq-crystals FIPS 204), the
Boschini R-LWE construction has no second independent implementation to
diff against. Therefore Corona's combine byte-equality is **asserted +
same-construction-KAT-tested**, never "proven/verified" in the
≥2-independent-implementations sense. `PROOF-CLAIMS.md` is worded to never
claim otherwise.

**Resolution criteria:**
- [ ] An independent R-LWE verifier (third-party or a from-the-paper
      re-implementation) is stood up and the KAT manifest diffs against it, OR
- [ ] External review accepts the same-construction KAT + code-review
      posture as sufficient for the disclosed tier (shared external-review
      gate).

## Closed

(none yet)
