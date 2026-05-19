# Contributing to Corona

## What we accept

This repository is **both** a production Ring-LWE threshold signature
library for Quasar consensus AND a NIST-MPTC-track submission
package. Until the 2026-Nov-16 package submission, contributions that
align with the MPTC submission are highest priority:

1. **Specification clarity** — text edits that disambiguate `SPEC.md`,
   `DESIGN.md`, and the LaTeX paper sections at
   `papers/lp-073-pulsar/`.
2. **Reference implementation** — `sign/`, `threshold/`, `dkg2/`,
   `reshare/`, `primitives/`, `hash/`. Boring, clear, no assembly,
   no clever abstractions. Match the spec section-by-section.
3. **Test vectors** — `cmd/*_oracle*/`. KAT-deterministic regeneration
   via `scripts/regen-kats.sh`; cross-runtime byte-equality with the
   C++ port at `~/work/luxcpp/crypto/corona/`.
4. **Constant-time analysis** — `CONSTANT-TIME-REVIEW.md`. Show,
   don't claim. New entries must cite the relevant Go source line +
   the upstream primitive's CT guarantee.
5. **Fuzz harness expansion** — `reshare/fuzz_*_test.go`,
   `dkg2/fuzz_round_test.go`, `threshold/fuzz_round_test.go`.
6. **Cryptanalysis of the Boschini et al. construction or Corona's
   production lifecycle additions** — open an issue. We track
   external review explicitly.

## What we don't accept

Until after the MPTC submission lands:

- New protocol features beyond what the Boschini et al. construction
  + Corona's production lifecycle layers specify.
- Optimized implementations (AVX2, SIMD, hand-rolled assembly) in
  the reference. Optimized implementations belong in a separate
  build tag and require independent CT audit.
- HSM integration patches in the reference (those belong in a
  separate consumer-side adapter library).
- Production-deployment patches in the reference (use the consuming
  consensus layer for deployment-specific orchestration).
- BLAKE3 hash-suite expansions — the NIST profile uses cSHAKE256 /
  KMAC256 / TupleHash256 exclusively (Corona-SHA3). The legacy
  Corona-BLAKE3 suite is retained for cross-port byte checks only;
  new BLAKE3 deltas should NOT land.
- Patches that introduce Pulsar (M-LWE) types into Corona (R-LWE).
  The two libraries are independent with no shared types; keep
  them that way.

These reopen post-submission.

## Process

1. **Open an issue first.** Discuss the change before implementing.
2. **One concern per PR.** Don't bundle spec edits with implementation
   changes. The MPTC review process treats them as separate artifacts.
3. **CI must pass.** Build, test, KAT regeneration, KAT cross-runtime
   verify, lattice-estimator (when wired) all green before merge.
4. **Sign your commits.** GPG-signed, real name in `Signed-off-by`.
   Patent-claim disclosures attach to commits.

## Development setup

```bash
git clone https://github.com/luxfi/corona
cd corona
./scripts/build.sh
./scripts/test.sh
./scripts/gen_vectors.sh
./scripts/regen-kats.sh --verify    # cross-runtime byte-equality check
```

LaTeX spec build (paper sections):
```bash
cd papers/lp-073-pulsar/
pdflatex lp-073-pulsar-pedersen-dkg.tex
pdflatex lp-073-pulsar-resharing.tex
```

## Coding standards (Go reference)

- Go 1.26.3+ (per `go.mod`).
- All logging via `github.com/luxfi/log` (consumer-supplied; the
  reference itself avoids logging on secret-touching paths).
  **No `log.Println`, `log.Fatalf`, `fmt.Printf`** in code that
  touches a secret.
- All secret-byte comparison via `crypto/subtle.ConstantTimeCompare`
  or the local `constTimePolyEqual` helper in `dkg2/dkg2.go:560`.
- All Gaussian sampling via lattigo's `KeyedPRNG`-backed
  `ring.NewGaussianSampler`. Direct `math/rand` is forbidden.
- All hash usage via `hash.HashSuite` injection — never hardcode
  cSHAKE256 / KMAC256 / TupleHash256 outside `hash/sp800_185.go`.
  Direct `golang.org/x/crypto/sha3` use is restricted to that file
  and the legacy `hash/blake3.go` for the cross-port byte-check
  suite only.
- All Sign-path primitives take `suite hash.HashSuite` as their
  first argument (per F22 closure in `CHANGELOG.md`).
- Errors carry context via `fmt.Errorf("%w", err)` not bare panics.
- Patch-bump only — `v0.4.1` → `v0.4.2`. Minor/major bumps require
  explicit approval (per `CLAUDE.md` rules).

## Hash-suite discipline

- Production: `hash.Default()` resolves to `Corona-SHA3`.
- Legacy: `hash.NewCoronaBLAKE3()` for cross-port byte checks ONLY.
- Adding a new suite requires updating `hash/sp800_185.go` with the
  customization strings, regenerating ALL KAT vectors, and updating
  the spec (`SPEC.md` §13).

## License

By contributing, you agree your contribution is licensed under
Apache-2.0 and grant the patent license described in the Apache 2.0
§3, AND the Corona-specific patent grant in `PATENTS.md` §3.

For NIST MPTC submission: contributions are subject to the
patent-claim disclosures collected in `docs/patent-claims.md`.
