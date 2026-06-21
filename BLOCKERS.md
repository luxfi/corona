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

### CORONA-EC-RECON-MODEL (HIGH — proof-scope disclosure)

**Status: OPEN. Disclosed, not closed.** The EasyCrypt Class N1
byte-equality theorem (`corona_n1_byte_equality` /
`corona_n1_byte_equality_extracted`) is machine-checked structurally
(0 admits) but proved **relative to** the bucket-C asserted axioms in
`AXIOM-INVENTORY.md` §C:

- `combine_body_spec` (the atomic Jasmin byte-walk) — the **Boschini
  combine steps 2–6 (open/aggregate/reject) are INSIDE this axiom,
  unproved.**
- `combine_abs_op_lifted_bridge` + `sign_abs_op_lifted_eq_rlwe` — the
  wrapper bridges that pin the lifted combine/sign op to
  `rlwe_sign_op (reconstruct quorum shares) …`, i.e. the centralised
  R-LWE signer applied to the **Lagrange-reconstructed master secret**.
- `combine_body_axiom` / `S_functional_spec` — the section-local module
  contracts of the same identity.

So the EC model **reconstructs the master key and signs with it**
(reconstruct-then-sign). This is an idealised *correctness* statement; it
is NOT a proof that the production threshold path is leak-free, and it is
NOT how the production path is intended to run.

**Resolution criteria:**
- [ ] Jasmin combine/sign byte-walk lands (production target v0.8.0) ⇒
      `combine_body_spec` / `sign_body_spec` and the layout-frame axioms
      become lemmas against the Jasmin operational semantics.
- [ ] Wrapper bridges (`combine_abs_op_lifted_bridge`,
      `sign_abs_op_lifted_eq_rlwe`, `combine_abs_op_lifted_bridge`)
      discharge to lemmas, OR are replaced by a faithful (non-reconstruct)
      model of the Boschini steps 2–6.
- [ ] `combine_body_axiom` / `S_functional_spec` discharge to lemmas via
      the wrapper instantiation against the extracted modules.
- [ ] **External cryptographic review** (shared gate with
      CORONA-CT-PENDING and CORONA-NO-INDEP-VERIFIER below) signs off that
      the reconstruct-then-sign EC model is an acceptable correctness
      idealisation given the separate code-review + KAT evidence.

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
