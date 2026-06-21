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
`Crypto.Threshold_Lagrange`. The EC side of Model 2 is **written,
machine-recheck pending EasyCrypt** (no `ec` on the authoring host;
`scripts/checks/ec-compile.sh` is the CI gate).

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
- [ ] `Corona_N1_NoLeak.ec` passes `scripts/checks/ec-compile.sh` in CI
      (machine-recheck pending EasyCrypt; cannot run on the authoring host).
- [ ] `no_leak_reduction` discharged to a full M-LWE/M-SIS simulation proof
      (v0.8.0), OR accepted by external review as a standard reduction.
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
