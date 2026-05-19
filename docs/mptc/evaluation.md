# Experimental Evaluation Report — Corona

> Per NIST IR 8214C §6 — Report on Experimental Evaluation.
> Companion to `SUBMISSION.md` cover sheet and `SPEC.md`
> construction specification.

## §1 Reproducibility commitment

Every measurement in this document MUST reproduce on a fresh checkout
of the submission tag under the documented hardware envelope, within
±5% drift. Drift outside that band is a build bug; please file an
issue.

Reproduction:

```bash
git clone --branch submission-2026-11-16 https://github.com/luxfi/corona
cd corona
scripts/build.sh
scripts/bench.sh    # writes bench/results/ with hardware fingerprint
```

The bench script captures hardware fingerprint (CPU brand, core
count, memory, Go version) so reviewers can compare environments.

## §2 Hardware envelope

Reference measurements at this submission scaffolding revision were
taken on the following envelope. Reviewers reproducing on different
hardware should expect proportional drift.

| Component | Reference value |
|---|---|
| CPU | Apple M2 Pro (10 cores) / Intel Xeon (cloud-equivalent) |
| Memory | ≥ 16 GiB |
| OS | macOS 25.4 / Linux x86_64 |
| Go version | 1.26.3 (pinned in `go.mod`) |
| `luxfi/lattice/v7` version | v7.1.0 (pinned in `go.mod`) |
| Build flags | default `go test -bench=. -benchmem` (no SIMD intrinsics; no assembly) |

Note: `scripts/bench.sh` writes the actual fingerprint captured at run
time to `bench/results/fingerprint.txt`. Use that file (not this
table) as the authoritative environment record for any specific
benchmark output committed to the repository.

## §3 Correctness evidence

### §3.1 Test coverage

| Suite | Tests | Location |
|---|---|---|
| `sign/` round-trip + suite-variant | 10+ | `sign/sign_test.go`, `sign/sign_roundtrip_test.go` |
| `threshold/` 2-round + batch verify | 15+ | `threshold/threshold_test.go`, `threshold/verify_batch_test.go` |
| `dkg2/` Pedersen DKG | 10+ | `dkg2/dkg2_test.go` |
| `dkg2/` fuzz | wired | `dkg2/fuzz_round_test.go` |
| `reshare/` Refresh + ReshareToNewSet | 45+ | `reshare/*_test.go` (multiple files) |
| `reshare/` fuzz | wired | `reshare/fuzz_*_test.go` (3 harnesses) |
| `primitives/` Shamir + hash | 10+ | `primitives/*_test.go` |
| `hash/` Corona-SHA3 + BLAKE3 + NIST SP 800-185 KAT | 5+ | `hash/hash_test.go` (`TestKMAC256NISTVector`, `TestTupleHash256NISTVector`) |

Run all tests:

```bash
GOWORK=off go test -count=1 -race ./...
```

### §3.2 KAT cross-runtime byte-equality

The Go reference and the C++ port at `~/work/luxcpp/crypto/corona/`
emit byte-identical KAT vectors. Enforcement:

```bash
scripts/regen-kats.sh           # write fresh KAT manifest
scripts/regen-kats.sh --verify  # compare against committed manifest
```

The manifest at `scripts/regen-kats.manifest.sha256` pins SHA-256 of
every regenerated KAT file. Five oracle generators:
- `cmd/corona_oracle_v2/` — sign / verify KAT (Corona-BLAKE3 legacy)
- `cmd/cross_runtime_oracle/` — cross-language byte-equality vectors
- `cmd/dkg2_oracle/` — Pedersen DKG transcripts
- `cmd/reshare_oracle/` — Refresh + ReshareToNewSet transcripts
- `cmd/activation_oracle/` — activation cert vectors

## §4 Performance — single-party signing

Reference Corona single-party sign + verify benchmarks (representative
order of magnitude; actual numbers depend on hardware and Go version):

| Operation | Time (M2 Pro) | Memory |
|---|---|---|
| `sign.Sign` (single-party kernel) | ~ 1–5 ms | < 1 MB |
| `sign.Verify` | ~ 0.5–2 ms | < 1 MB |
| `primitives.PRNGKey` (Corona-SHA3) | < 100 µs | < 1 KB |
| `primitives.GaussianHash` | < 500 µs | < 1 KB |

Specific numbers MUST be regenerated via `scripts/bench.sh` on the
reviewer's environment; reference values above are order-of-magnitude
expectations, not guaranteed performance.

## §5 Performance — threshold signing

Threshold signing has higher cost than single-party (2 broadcast
rounds + Lagrange aggregation). Representative cost factors:

| Parameter | Effect on cost |
|---|---|
| Quorum size `t` | Linear in Round 1/2 message count |
| Committee size `n` | Linear in Pedersen DKG cost; affects Lagrange-coefficient precomputation cost |
| Network RTT | Dominates over local compute for small `t` |
| `verify_batch.VerifyBatch` | O(N) verification of N signatures parallelized via goroutines (`threshold/verify_batch.go` since v0.4.1) |

For specific (n, t) measurements, run `scripts/bench.sh` and inspect
`bench/results/go-bench.txt`.

## §6 Performance — DKG

Pedersen DKG over `R_q` (`dkg2/`) has cost dominated by:

- Per-party polynomial sampling (`t` coefficients × `M` polynomials in
  `R_q^M`, each requiring discrete-Gaussian sampling).
- Pedersen commit computation: `M` per-coefficient commits of the
  form `A·NTT(s^(k)) + B·NTT(r^(k))`.
- Per-pair encrypted-share exchange under authenticated KEX.
- Complaint-round verification: `O(n · M)` per-coordinate
  constant-time `eq &=` accumulation.

Reference cost: full DKG (`n = 7, t = 4`) completes in seconds on the
M2 Pro envelope; full DKG (`n = 32, t = 22`) completes in tens of
seconds. Network RTT is the dominant cost factor in production
deployments.

## §7 Performance — proactive resharing

Reshare cost is dominated by:

- Per-old-party fresh polynomial sampling.
- Per-pair `g_i(β_j)` delivery (encrypted).
- Per-new-party Lagrange recombination over the old qualified subset.
- Activation cert: one threshold signature under unchanged group key.

Reference cost: `ReshareToNewSet` for committee size 7 → 7 completes
in single-digit seconds on the M2 Pro envelope; activation cert adds
~ 1 signing-session cost.

## §8 Side-channel evidence

### §8.1 Static constant-time audit

Per `CONSTANT-TIME-REVIEW.md`:
- Zero `(c)` (must-fix) entries.
- Two `(b)` entries documented with mitigations:
  1. `reshare/commit.go:124` — legacy reshare path Pedersen mismatch;
     fixed-in-place in `dkg2/` via `constTimePolyEqual`. Legacy
     `reshare` path scheduled for migration.
  2. `lens/primitives/secp256k1.go` — non-CT scalar mul; off the
     Corona threshold path.

### §8.2 Statistical CT validation

NOT delivered at this submission. dudect-style harness is roadmap
item v0.8.0. At submission scaffolding, the CT evidence reduces to
the static audit + upstream lattigo CT claims.

## §9 Security-parameter evidence

### §9.1 Parameter set

Corona v0.4.1 ships a single parameter set:
- Ring degree `N = 256`
- Prime `q = 0x1000000004A01` (48-bit NTT-friendly)
- Module width `M = 8`, height `N_M = 7`
- Challenge weight `Kappa = 23`

### §9.2 Concrete security claim

Target: ≥ 128 bits of post-quantum security against the best known
R-LWE attacks per the lattice-estimator methodology of
Albrecht-Player-Scott.

**Roadmap**: a worksheet with concrete lattice-estimator output for
the parameter set is roadmap item v0.6.0. At submission scaffolding
this revision, the concrete bounds are NOT included; the parameter
set was chosen by Lux engineering against the academic R-LWE
literature, but the documented worksheet is pending.

### §9.3 R-LWE prior art

Underlying construction: Boschini, Kaviani, Lai, Malavolta, Takahashi,
Tibouchi. *Practical two-round threshold signatures from learning
with errors.* IACR ePrint 2024/1113, IEEE S&P 2025. EUF-CMA reduction
in §3 of the paper. Corona inherits the analysis.

R-LWE primitive: Lyubashevsky, Peikert, Regev. *On ideal lattices and
learning with errors over rings.* EUROCRYPT 2010.

Concrete cryptanalysis literature: Albrecht, Player, Scott. *On the
concrete hardness of learning with errors.* J. Math. Cryptol. 2015
(lattice-estimator methodology). Plus follow-up cryptanalysis at
IACR ePrint archive 2015–2026.

## §10 What this report does NOT include

- Specific numeric benchmarks (run `scripts/bench.sh` locally; the
  bench script writes the actual numbers + fingerprint).
- Concrete lattice-estimator output for the parameter set (roadmap
  v0.6.0).
- Comparison benchmarks against single-party FIPS 204 ML-DSA — Corona
  and ML-DSA are different lattice families; like-for-like comparison
  is not meaningful.
- Threshold-vs-single-party overhead measurements at specific (n, t)
  — these depend heavily on network conditions in production; the
  reference benchmark suite measures the local compute portion.
- HSM-backed share-management performance — that is consumer-side.

---

**Document metadata**

- Name: `docs/mptc/evaluation.md`
- Version: v0.1 (initial submission-package scaffolding)
- Date: 2026-05-18
