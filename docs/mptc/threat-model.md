# Corona — Threat Model

> Companion to `SPEC.md` §4 and `SUBMISSION.md` headline claim.
> This document specifies the adversary model, security goals, and
> trust boundaries for the Corona threshold signing system.

## §1 The participants

| Role | Description |
|---|---|
| **Committee** `O` | The set of `n` parties participating in DKG and signing. |
| **Quorum** `Q ⊆ O` | A subset of `t` parties (the signing threshold) that collectively sign. |
| **Aggregator** | The party (typically the consensus block proposer) that collects Round-1 commits and Round-2 responses, computes the Lagrange aggregation, and produces the final signature. |
| **Bootstrap Dealer** | The party (or MPC ceremony) that runs the one-time trusted-setup at chain genesis. Foundation MPC node; never holds unencrypted secrets after the ceremony close. |
| **Signature Coordinator** | The operational party (typically the consensus block proposer) that triggers signing sessions. Distinct from the Bootstrap Dealer; holds no membership-management authority. |
| **Verifier** | Any party (validator, light client, observer) running `sign.Verify(group_pk, m, σ)`. No threshold-specific state required. |

## §2 The adversary

### §2.1 Adversary capabilities

The Corona EUF-CMA-Threshold claim assumes a **rushing Byzantine
adversary** with the following capabilities:

| Capability | Allowed? |
|---|---|
| Static corruption of up to `t − 1` parties | YES |
| Adaptive corruption of up to `t − 1` parties | OUT OF SCOPE at this submission (paper proves adaptive in random oracle model, but Corona's mechanization is paper-cited; no Corona-specific machine-checked adaptive proof) |
| Rushing (see all honest messages in a round before sending its own) | YES |
| Network message reordering up to bounded delay `Δ` | YES |
| Eavesdropping on all broadcast messages | YES |
| Active modification of broadcast messages | YES (Byzantine adversary; messages are signed and complaints expose tampering) |
| Asynchronous corruption / late corruption mid-session | OUT OF SCOPE |
| Quantum computer | YES — the construction is post-quantum (R-LWE) |
| Side-channel observation | OUT OF SCOPE for the math; addressed at the implementation layer via `CONSTANT-TIME-REVIEW.md` and `DEPLOYMENT-RUNBOOK.md` hardening checklist |

### §2.2 Adversary cannot

| Capability | Disallowed |
|---|---|
| Corrupt more than `t − 1` parties (i.e., reach a quorum unilaterally) | DISALLOWED — assumption breaks EUF-CMA reduction |
| Read the master secret `s` post-Bootstrap | DISALLOWED — `s` is never assembled in any honest party's memory after Bootstrap |
| Forge a signature without a quorum | DISALLOWED — EUF-CMA reduction in Boschini et al. ePrint 2024/1113 §3 |
| Cause `(A, bTilde)` to change without a Reanchor governance event | DISALLOWED — invariant enforced by activation cert circuit-breaker |
| Roll back the chain by manipulating reshare timing | DISALLOWED — LSS `RollbackManager` controls rollback, gated by consensus |
| Compromise the Bootstrap MPC ceremony after its close | DISALLOWED — ceremony state is zeroed in place; subsequent compromise yields no `s` material |

## §3 Network model

### §3.1 Synchronous network (the assumed model)

- Bounded message delivery: every honest-to-honest message arrives
  within delay `Δ`.
- All parties have approximately-synchronized clocks (within `Δ`).
- Round timeouts are configured at the consensus layer per the
  expected `Δ` of the deployment.

Under the synchronous model, Corona's identifiable-abort property
holds: a misbehaving party can be uniquely identified from the
protocol transcript with high probability.

### §3.2 Asynchronous / partition (NOT supported)

- Identifiable abort under network partition is OUT OF SCOPE.
- Corona's complaint mechanism relies on timely message delivery;
  if messages are delayed beyond `Δ`, the complaint mechanism may
  produce false-positive accusations or fail to identify the actual
  attacker.
- For asynchronous identifiable abort, see the separate Z-Chain
  Groth16 accountability layer (NOT part of this submission).

### §3.3 Eclipse attacks

- A successful eclipse attack against an aggregator (controlling all
  network paths to and from the aggregator) reduces to the
  aggregator-host-compromise threat addressed in
  `DEPLOYMENT-RUNBOOK.md`.
- Operationally mitigated via TEE attestation and multi-coordinator
  rotation per consensus deployment.

## §4 Cryptographic assumptions

### §4.1 Underlying hardness

| Assumption | Where used |
|---|---|
| Ring-LWE hardness over `R_q = Z_q[X]/(X^N + 1)` with `N = 256`, `q = 0x1000000004A01` | Inherits EUF-CMA reduction from Boschini et al. ePrint 2024/1113. |
| Ring-SIS hardness (informally; the construction's reduction passes through SIS in the random oracle model) | Same paper. |
| cSHAKE256 / KMAC256 / TupleHash256 collision and preimage resistance | All transcript hashes, MAC derivation, PRF derivation. |
| Random oracle model | The EUF-CMA reduction in Boschini et al. relies on ROM. |

### §4.2 Concrete-security target

- ≥ 128 bits of post-quantum security per the lattice-estimator
  methodology of Albrecht-Player-Scott (2015) and follow-ups.
- The Corona parameter set was chosen to meet this target; concrete
  lattice-estimator output is roadmap item v0.6.0.

### §4.3 What this DOES NOT cover

- Lattice-cryptanalysis breakthroughs that reduce R-LWE security
  parameters below current estimates.
- Quantum-cryptanalytic breakthroughs against the random oracle
  model.
- Discovery of an efficient ring-structure-specific attack on
  Boschini et al.'s ROM-based reduction.

Corona tracks cryptanalysis literature; any flaw would prompt a
parameter-set re-tune and a new key-era via the Reanchor mechanism.

## §5 DKG threat model

### §5.1 In scope for `dkg2/` (Pedersen DKG over `R_q`)

- A malicious dealer attempts to bias the group public key — DEFENDED:
  Pedersen hiding blinds ensure the commitment leaks no information
  beyond what is necessary for verification.
- A malicious dealer attempts to deliver inconsistent shares to
  different recipients — DEFENDED: per-pair Pedersen verification +
  complaint round + qualified-set selection.
- A malicious recipient falsely accuses an honest dealer — DEFENDED:
  signed complaint messages with publicly-verifiable evidence;
  false accusations are detectable.
- A subset of `< t` malicious parties attempts to learn `s` —
  DEFENDED: standard Shamir threshold guarantee.

### §5.2 Out of scope for `dkg2/`

- A fully colluding `n` parties (no honest majority): trivially
  break — no defense.
- A network-layer attacker delaying complaints past the round
  timeout: handled at the consensus layer.
- Bias resistance under collusion of `t` parties (a colluding
  quorum can bias the group key): production deployments bind a
  randomness beacon at the consensus layer for additional
  bias-resistance.

### §5.3 Legacy `dkg/` (Feldman VSS — broken for public broadcast)

The legacy `dkg/` package uses Feldman-style commits without hiding
blinds and IS BROKEN under public broadcast (see upstream
`RED-DKG-REVIEW.md` Findings 5/6). Production deployments MUST NOT
use `dkg/`; use `dkg2/` instead. `dkg/` is retained ONLY for
historical reference and reading existing test fixtures.

## §6 Reshare threat model

### §6.1 In scope for `reshare/`

- Old qualified subset `Q ⊆ O_old` with at most `t_old − 1`
  malicious parties: DEFENDED — `|Q| ≥ t_old` requirement ensures
  at least one honest old-party contributes to every new share.
- Malformed share delivery from old party to new party: DEFENDED —
  Pedersen-style per-pair verification; complaint mechanism.
- Activation cert forgery attempt: DEFENDED — activation cert is a
  threshold signature under the unchanged `(A, bTilde)`; forgery
  reduces to EUF-CMA which is the same hardness as the underlying
  scheme.
- Race condition where new committee accepts before old committee
  finishes: DEFENDED — activation cert gating ensures new committee
  cannot be accepted until math + verification complete.

### §6.2 Out of scope for `reshare/`

- Cross-key-era preservation (new key era after Reanchor): governance
  event, separate threat model.
- Identifiable abort under network partition (see §3.2).
- Robustness against `≥ t/2` Byzantine parties in the old set:
  honest-majority assumption.

## §7 Signing threat model

### §7.1 In scope for `sign/` + `threshold/`

- EUF-CMA against quantum adversary: inherited from Boschini et al.
  §3.
- Static corruption of `< t` parties during signing: DEFENDED.
- Replay attack: DEFENDED via `sid` (fresh per-session 32-byte
  randomness) binding into the transcript.
- Domain-confusion across message classes: DEFENDED via
  `QUASAR-CORONA-*` prefix discipline.
- Timing side-channel on the recipient-side verifier:
  DEFENDED via `CONSTANT-TIME-REVIEW.md` static audit (zero `(c)`
  findings).

### §7.2 Out of scope for `sign/`

- Aggregator-host compromise during a signing session: addressed at
  the deployment layer per `DEPLOYMENT-RUNBOOK.md` hardening
  checklist.
- Statistical timing side-channel: dudect-style validation is
  roadmap v0.8.0.
- Power / EM side-channels: not addressed; production deployments
  use TEE attestation.
- Fault attacks: not addressed.

## §8 Trust boundaries

### §8.1 What the chain trusts

- The Bootstrap MPC ceremony at chain genesis (one-time).
- The R-LWE construction's correctness (per Boschini et al.
  paper).
- The Go reference implementation's correctness (per code review +
  KAT + fuzz).
- The Corona-SHA3 hash suite (per FIPS 202 + SP 800-185).

### §8.2 What the chain does NOT trust

- Any individual validator (each is potentially malicious up to
  `t − 1` collusion).
- Any individual coordinator (rotates per epoch).
- The network layer beyond the synchronous-`Δ` model.
- The OS kernel of any single validator beyond the deployment
  hardening checklist.

### §8.3 What downstream consumers trust

- The Corona reference verifier `sign.Verify`.
- The cross-runtime byte-equality manifest (Go ↔ C++).
- The deployment runbook's hardening recommendations.
- The Reanchor governance procedure for security-incident response.

## §9 Side-channel threat model

### §9.1 In scope (per `CONSTANT-TIME-REVIEW.md`)

- Timing leakage on Pedersen commit verification: DEFENDED via
  `eq &=` constant-time slot accumulation in `dkg2/dkg2.go:560`.
- Timing leakage on verifier byte-equality: DEFENDED via Go
  fixed-size array equality (constant-time on amd64/arm64) and
  `subtle.ConstantTimeCompare` for variable-length byte blobs.
- Timing leakage on NTT / Montgomery / Gaussian sampling: DEFENDED
  via upstream lattigo constant-time guarantees.

### §9.2 Out of scope at this submission

- Cache-timing side channels: not addressed; production
  deployments use TEE attestation.
- Power side channels: not addressed.
- EM side channels: not addressed.
- Statistical timing validation (dudect): roadmap v0.8.0.

## §10 Failure-mode threat model (no-slashing-dependency)

Per `DESIGN.md` §"Bootstrap Dealer vs Signature Coordinator (LSS
roles, no-slashing semantics)". The failure response ladder:

```
1. Coordinator timeout / unavailable
   → consensus picks next coordinator deterministically.

2. Resharing round fails (commit mismatch, bad share, etc.)
   → emit signed evidence of the failure point; retry under new
     transcript binding next epoch.

3. Activation cert fails to verify under unchanged GroupKey
   → LSS Rollback(targetGeneration = current - 1); chain stays at
     previous generation; signing continues under previous shares.

4. Multiple consecutive activation failures
   → governance reanchor: new KeyEraID, fresh ceremony, new GroupKey.
```

No step requires identifying a malicious actor. Slashing evidence
is **collected** during steps 2-3 but the chain's liveness and
safety do not depend on attribution. This is the no-slashing-
dependency property.

---

**Document metadata**

- Name: `docs/mptc/threat-model.md`
- Version: v0.1 (initial submission-package scaffolding)
- Date: 2026-05-18
