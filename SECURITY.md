# Security policy

## Reporting vulnerabilities

Please report cryptographic or implementation vulnerabilities privately to
**security@lux.network** — encrypted with the team key listed at
`https://lux.network/security/key.asc`. Public disclosure happens after a
fix lands and downstream consumers have had a 14-day private window.

## What is in-scope

Corona is **production-hardened reference implementation** for
Ring-LWE threshold signing in Quasar consensus, and a NIST MPTC
submission package. The following are in-scope for responsible
disclosure:

- Specification ambiguity that leads to an exploitable verifier
  behaviour.
- Threshold-protocol soundness gaps (forgery, key-recovery, share
  extraction, rogue-key, adaptive-corruption breaks).
- Constant-time violations in code paths that touch a secret share,
  a Gaussian sample, or a Lagrange-aggregation intermediate.
- KAT mismatches between the Go reference and the C++ port at
  `~/work/luxcpp/crypto/corona/` (cross-runtime byte-equality is a
  load-bearing invariant).
- Pedersen DKG (`dkg2/`) hiding-blind leakage or commitment binding
  failures.
- Reshare-protocol (`reshare/`) failures to preserve `(A, bTilde)`
  across committee rotation.
- Activation-cert (`reshare/activation.go`) bypass or accept-on-
  failure paths.
- Information leaks via logging, panics on secret-correlated paths,
  or variable-time equality.
- Cryptanalysis of the underlying Boschini et al. ePrint 2024/1113
  construction or of Corona's specific parameter set (`N = 256`,
  `q = 0x1000000004A01`).

## What is NOT in-scope

- Performance or implementation efficiency complaints (file an issue).
- DoS attacks against the reference implementation that don't affect
  the threshold-correctness invariants.
- Issues exclusively in the M-LWE sibling at `luxfi/pulsar` — file
  there. Corona and Pulsar are independent libraries with no shared
  types.
- Issues in lens-specific code (`lens/`) — Corona's threshold path
  does not depend on lens.
- Issues in the legacy `dkg/` (Feldman VSS without blinding) —
  documented as broken for public broadcast; replaced by `dkg2/`
  (Pedersen DKG with hiding blinds). Production deployments use
  `dkg2/`.

## CVE assignment

Corona maintainers will request CVEs for any in-scope vulnerability
prior to public disclosure. CVE numbers will be embedded in the
ePrint changelog and the release tag's commit message.

## NIST MPTC submission disclosures

Findings discovered after the 2026-Nov-16 MPTC package submission
deadline will be added to the submission's "known limitations"
appendix and disclosed publicly per NIST's MPTC public-analysis
process (no embargo window for findings against actively-submitted
MPTC packages).

## Coordinated disclosure with Pulsar

Corona and Pulsar are independent submissions but share Lux as a
common author and overlap in some operational mitigations (e.g.,
aggregator-host hardening, mlock pinning). A vulnerability that
affects both packages will be disclosed to both `security@lux.network`
mailing lists simultaneously to enable coordinated patching.

## Disclosure timeline (default)

- T+0: Private report received at security@lux.network.
- T+5 days: Acknowledgement + initial triage; CVE requested if
  in-scope.
- T+30 days: Fix landed in `main`; tagged patch release; private
  disclosure to downstream consumers (Quasar consensus, etc.).
- T+44 days: Public disclosure (advisory + CVE published).

Faster disclosure timelines apply for critical findings (immediate
exploitability with no mitigation). Slower timelines apply for
research-level findings requiring spec consultation with NIST MPTC
reviewers.
