# Pulsar -- Agent Knowledge Base

**Repository**: github.com/luxfi/pulsar
**Latest Tag**: v0.1.5
**Status**: Production (consensus path); sibling project `luxfi/pulsar-m` is the M-LWE submission to NIST MPTC.

## Purpose (one-liner)

Ring-LWE threshold signature library used as the post-quantum threshold
layer in Quasar consensus. Pulsar provides O(1) per-cert proofs after
DKG, paired with BLS12-381 + ML-DSA-65 in the QuasarCert.

## Post-E2E-PQ State (current)

Pulsar is the canonical R-LWE threshold for consensus (Q-Chain). Pulsar-M
(this repo's M-LWE sibling at `luxfi/pulsar-m`) handles ML-DSA threshold
for the identity layer; the two do not overlap in role.

### Recent significant commits

| SHA | Tag | Impact |
|-----|-----|--------|
| `4043d76` | v0.1.5 | Bump Go toolchain 1.26.2 → 1.26.3 (govulncheck CVE) |
| `88fdb8a` | v0.1.5 | Bump Go toolchain 1.26.1 → 1.26.2 (govulncheck CVE) |
| `930a628` | v0.1.5 | gofmt -s across cmd/ + reshare/ + dkg2/ + keyera/ + threshold/ |
| `5dee925` | v0.1.5 | Plumb HashSuite through every Sign-path primitive (F22) |
| `0c7680e` | v0.1.2 | LP-107 Phase 4: pulsar consumes luxfi/math/codec |
| `39632ed` | v0.1.2 | Cross-runtime oracles + sign KAT generator |
| `f9113d7` | v0.1.2 | Validate Vector[Poly] frame before lattigo ReadFrom |
| `d5606e9` | v0.1.0 | Lattice threshold kernel + key-era lifecycle + Pulsar-SHA3 + Nebula binding |

### Active versions
- Repo: `v0.1.5` (next: `v0.1.6`).
- Pinned by: `luxfi/consensus v1.23.6+` (R-LWE path is consensus-only).

### Canonical params
- Ring degree: 256 (LogN=8).
- M=8, N=7, Dbar=48, Kappa=23.
- Q=0x1000000004A01 (48-bit NTT-friendly prime).
- Hash suite: Pulsar-SHA3 (KMAC over cSHAKE256), `pulsar/hash/sp800_185.go`.

### Cross-repo dependencies
- `luxfi/math/codec` → wire codec (LP-107 Phase 4).
- `luxfi/lattice/v7` → lattigo-backed polynomial ops.
- Consumed by:
  - `luxfi/consensus/protocol/quasar` (R-LWE threshold for QuasarCert).

### Where to look for X
- Threshold kernel: `threshold/`
- DKG (epoch lifecycle): `dkg2/`
- Pulsar-SHA3 / KMAC: `hash/sp800_185.go`
- Key-era management: `keyera/`
- Reshare: `reshare/`

### Open follow-ups
- Variable-size R-LWE certs are still a wire-size cost vs the M-LWE
  Pulsar-M path; consensus uses Pulsar for finality-throughput and
  Pulsar-M for the identity rollup.

## Rules

1. Patch-bump only.
2. HashSuite is the only acceptable hash plumbing (F22 closure); never
   hardcode SHAKE / KMAC outside `hash/sp800_185.go`.
3. Param changes require a new key-era boundary; never edit in place.
