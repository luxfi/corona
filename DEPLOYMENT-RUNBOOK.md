# Deployment Runbook — luxfi/corona

> Operational guidance for deploying Corona (threshold Ring-LWE
> signing + Pedersen DKG + proactive resharing) in production
> validator sets. Discloses the v0.2 trust-model caveats and pins
> the safe operating envelope.

## Audience

- Validator operators bringing up a Corona-enabled Lux Quasar chain
  (or any chain consuming `github.com/luxfi/corona`).
- Coordinator-service operators running the witness-aggregator
  pattern.
- Security reviewers validating production posture against the
  honest framing in `PROOF-CLAIMS.md`.

## Trust-model disclosure (load-bearing)

### The v0.2 reconstruction-aggregator caveat

> **Operators MUST acknowledge this before running v0.2 in production
> on funds-bearing networks.**

Corona's combine procedure operates on Lagrange-aggregated `z_i =
y_i + c·s_i` responses. The aggregator computes
`z = Σ_{i ∈ Q} λ_i^Q · z_i` over `R_q^M`. The aggregator does NOT
reconstruct the master secret `s` in memory at any point during
normal signing — the Lagrange aggregation is over the partial
responses, not the shares themselves.

**However**, two distinct trust-model caveats apply:

1. **DKG bootstrap is a one-time trusted-setup event.** At chain
   genesis (or at Reanchor), the foundation MPC ceremony runs
   `keyera.Bootstrap` which generates the master secret `s` and
   distributes shares. Whoever participates in the Bootstrap MPC
   ceremony has, at some point in the ceremony's execution, machinery
   that touches `s`. The dealer-side `s` is zeroed in place after
   sharing (`keyera/keyera.go:191-198`), but the ceremony must be
   conducted under verifiably-public conditions (commit-and-reveal
   from genesis validators) with toxic-waste assumptions tracked.

2. **The aggregator process is in the trusted computing base.** An
   adversary who fully compromises the aggregator host
   (root-equivalent) during a signing session can observe `c` and
   `z_i` for all `i ∈ Q`, and can compute `s_Q = Σ λ_i · s_i` if it
   sees enough partial-response sets across distinct quorum subsets.
   (Note: this is weaker than Pulsar's v0.1 aggregator caveat, where
   the aggregator briefly reconstructs the master ML-DSA seed in
   memory; Corona's aggregator never reconstructs `s`.)

**Operational mitigations** (all production deployments MUST
satisfy at least items 1–4):

1. **Aggregator host hardening**: dedicated host, no general-purpose
   workloads, no shared memory, no /proc access for non-root users,
   hugepages disabled (prevents same-page deduplication side-channels).
2. **Memory isolation**: the aggregator process runs with locked
   pages (`mlock`), core-dumps disabled (`setrlimit RLIMIT_CORE=0`),
   ptrace disabled (`prctl PR_SET_DUMPABLE 0`).
3. **Bootstrap MPC ceremony hardening**: foundation MPC ceremony at
   chain genesis uses commit-and-reveal entropy from genesis
   validators; dealer state is zeroed in place via
   `keyera/keyera.go:Bootstrap`. Ceremony participants are bound by
   the foundation's toxic-waste protocol.
4. **Operational scope limits**: aggregator role is a single-purpose
   process; no network listener beyond the consensus message bus;
   no shell access; no debugger attachment in production.
5. **TEE attestation (recommended)**: aggregator runs inside SGX,
   SEV-SNP, or TDX with remote attestation pinned to the
   reproducible build of `luxfi/corona v0.4.1`.
6. **Defense-in-depth**: validator-set rotation via Reshare (not
   Reanchor) is the routine path; Reanchor (new key era) is a rare
   governance event reserved for security-incident response.

### What Corona's combine does NOT do

- Does NOT reconstruct the master secret `s` in aggregator memory
  during normal signing.
- Does NOT persist any per-party share to disk during signing.
- Does NOT leak any per-party share to any other process under
  normal operation.
- Does NOT survive a process crash with secret share material
  present beyond the Go runtime's normal garbage-collection cycle
  (best-effort zeroization via `reshare/keyshare.go:EraseShare` is
  invoked on activation and reshare-completion paths).

## Pre-deployment checklist

Before bringing up a Corona-enabled validator:

- [ ] Operator-readable acknowledgement of the v0.2 trust caveats
      above on file (RACI sign-off).
- [ ] Aggregator host meets items 1–4 above.
- [ ] If running on funds-bearing mainnet: item 5 (TEE attestation)
      satisfied OR documented compensating control approved by
      security review.
- [ ] `scripts/build.sh` exits 0 against the deployed binary's
      source tag (i.e., the binary you are deploying was built from
      a commit where the build gates were green).
- [ ] `scripts/test.sh` exits 0 against the deployed tag (KAT +
      integration + unit tests green).
- [ ] `scripts/regen-kats.sh --verify` exits 0 (cross-runtime
      byte-equality with the C++ port is intact).
- [ ] `CONSTANT-TIME-REVIEW.md` reviewed; all `(b)` entries either
      mitigated or accepted with documented compensating control.
- [ ] `PROOF-CLAIMS.md` §3 read and understood — Corona does NOT
      ship mechanized refinement; review reduces to code + KAT +
      academic construction analysis.
- [ ] `DESIGN.md` §"What is preserved across resharing" understood
      — distinguish Refresh (same set, fresh shares) from
      ReshareToNewSet (set rotation), distinguish Reshare (preserves
      key era) from Reanchor (new key era).
- [ ] Validator-set rotation policy documented (cadence, threshold
      changes, complaint-response procedures).

## At-runtime monitoring

The aggregator process should expose:

- A metric for every `threshold.Combine` invocation (counter +
  latency-histogram).
- A metric for every Lagrange aggregation step (counter; should
  match Combine invocations 1:1).
- A metric for every share zeroize call on the post-activation
  path (counter; should match activation completions 1:1).
- A metric for every Pedersen-mismatch complaint event (counter;
  should be 0 in honest deployments — spike indicates a malicious
  participant).
- A panic / signal handler that invokes `EraseShare` on the current
  generation's shares before exit.

Anomalous values (e.g., a spike in complaints without a corresponding
disqualification, or a zeroize counter trailing the activation
counter) should page immediately.

## Resharing operational procedure

Corona's resharing is the routine path for validator-set changes
within a key era. See `DESIGN.md` §"Three layers, one shipping path"
for the algorithmic detail; operational specifics:

1. **Cadence**: every epoch boundary or every validator-set change,
   whichever is more frequent. The consensus layer (Quasar)
   triggers resharing via the `keyera.Reshare` call.

2. **Round structure**: 3-round shape (commit → private deliveries →
   combine + activate). Each round has a timeout configured at the
   consensus layer; missed rounds trigger the complaint pipeline.

3. **Complaint handling**: per-pair Pedersen-style verification on
   the recipient side (`dkg2.go:VerifyShareAgainstCommits` /
   `reshare/commit.go:VerifyShareAgainstCommits`). Failure produces
   a signed evidence packet identifying the malicious sender.
   Disqualification quorum is configured at the consensus layer.

4. **Activation gate**: after the math completes, the new committee
   threshold-signs an activation message under the **unchanged**
   `(A, bTilde)`. Only on successful verification does the chain
   accept the new epoch. Failure → consensus falls back to the old
   committee + retries with a new transcript binding.

5. **Failure modes**:
   - Coordinator timeout / unavailable → consensus picks the next
     coordinator deterministically.
   - Resharing round fails (commit mismatch, bad share) → emit signed
     evidence; retry under new transcript binding next epoch.
   - Activation cert fails to verify → LSS Rollback to previous
     generation; chain stays at previous generation; signing
     continues under previous shares.
   - Multiple consecutive activation failures → governance reanchor:
     new key era, fresh ceremony, new group key.

## Migration paths

### v0.4.x → v0.5.x (submission-package addition)

This revision adds the NIST MPTC submission package documentation
(`SUBMISSION.md`, `NIST-SUBMISSION.md`, `SPEC.md`, `PATENTS.md`,
`PROOF-CLAIMS.md`, `TRUSTED-COMPUTING-BASE.md`, etc.). NO behavior
changes. KAT vectors are byte-identical. Production deployments can
upgrade in place; no validator-set rotation required.

### v0.5.x → v0.6.x (planned)

Planned: single-document `spec/corona.tex` consolidating the LaTeX
spec, parameter-set worksheet with lattice-estimator concrete
bounds, and second parameter set targeting NIST PQ Category 3.
Backward-compatible at the wire level; may add a new parameter-set
identifier.

### v0.6.x → v0.7.x (research, multi-month)

Planned: EasyCrypt theory shell for the construction-level
interchangeability claim; Lean 4 / Mathlib mechanization of the
Lagrange-aggregation identity over `R_q`. NO code changes; pure
proof artifact addition. Backward-compatible.

### v0.7.x → v0.8.x (research + audit)

Planned: dudect-style statistical CT validation harness; external
cryptographic audit (engaged lab). May surface findings requiring
patch-level remediation.

## Reference: cryptographer guidance

Corona does NOT ship a `CRYPTOGRAPHER-SIGN-OFF.md` at this submission
scaffolding revision. (Pulsar has one because Pulsar has an
EasyCrypt + Lean + Jasmin mechanized refinement chain that a
cryptographer signed off on. Corona's lighter proof tier does not
yet warrant analogous formal sign-off.) The roadmap to a Corona
sign-off lands with v0.7.0 (mechanized refinement) and v0.8.0
(external audit).

In the interim, the honest cryptographic posture is:

- **Construction soundness**: inherited from Boschini et al. ePrint
  2024/1113 (peer-reviewed academic prior art, IEEE S&P 2025).
- **Implementation soundness**: code review + KAT cross-validation
  Go ↔ C++ + fuzz harnesses + static per-path constant-time audit
  with zero `(c)` findings.
- **Lifecycle soundness**: production-tested via the consuming Quasar
  consensus layer; activation cert circuit-breaker is the
  load-bearing safety mechanism.

## Contact

- Operations: `ops@lux.network`
- Security: `security@lux.network`
- Submission package: `mptc@lux.network`

---

**Document metadata**

- Name: `DEPLOYMENT-RUNBOOK.md`
- Version: v0.1 (matches Corona v0.4.1; updated for submission scaffolding)
- Date: 2026-05-18
