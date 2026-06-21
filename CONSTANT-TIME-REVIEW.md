# Corona — constant-time review

**Scope:** every Corona code path that touches a secret share, the
per-signature nonce, a private commit opening, an arithmetic intermediate
that depends on a secret, or a digest compared against an
attacker-supplied value. Corona is a pure-Go threshold-Raccoon
(Module-LWE) signature; there are no curve operations and no `lens`/`warp`
surfaces — those belong to other repositories and are out of scope here.

**Status legend:**

- **(a)** Constant-time by construction; documented citation to the
  underlying primitive.
- **(b)** Variable-time, but every operand on the path is **public**
  (publicly derivable from the wire-format signature, the group key, or
  protocol metadata). The timing channel reveals nothing the result byte
  does not already disclose. Documented, not a secret leak.
- **(c)** MUST FIX before production; precise location captured.
- **(TCB)** Constant-time behaviour is **assumed of an upstream
  dependency**, not proven in this tree. Listed explicitly so the trust
  assumption is visible.

**Headline:** zero (c) entries. Every secret-dependent comparison in
Corona is `crypto/subtle.ConstantTimeCompare` over a byte view, or
fixed-size array equality (constant-time on amd64/arm64). The remaining
(b) entries are public-input paths. One (TCB) entry — the lattigo
discrete-Gaussian / uniform / ternary samplers — is the residual
assumption on which secret-seeded Round-1 sampling rests; it is asserted,
not mechanically proven here.

---

## 1. Per-signature nonce key (the no-leak-critical path)

| Location | Status | Notes |
|---|---|---|
| `primitives.DeriveSessionID` (`primitives/hash.go:75`) | **(a)** | Deterministic 256-bit session identifier `TranscriptHash("corona.sign.session-id.v1" \|\| be64(sid) \|\| T)`. Inputs `(sid, T)` are public consensus metadata; the function is a hash with no secret-dependent branching. Replaces the prior bare-64-bit-`sid` nonce keying. |
| `primitives.PRNGKeyForRound` (`primitives/hash.go:111`) | **(a)** | `PRF(skShare, "CoronaNonceV3" \|\| sessionID[32] \|\| salt[32])`. `skShare` is secret but is only fed as the PRF *key* to the suite PRF (KMAC256 under Corona-SHA3 / keyed BLAKE3 under the legacy suite) — keyed-hash absorption is constant-time in the key per the sponge/compression construction; there is no secret-dependent control flow. Output is the Round-1 nonce-PRNG seed. |
| `sign.Party.SignRound1` nonce guard (`sign/sign.go:151`) | **(a)** | Draws a fresh 32-byte hedge salt from `party.Rand` (default `crypto/rand.Reader`), so the nonce key — hence `R` — is fresh per signature even if the consensus layer reissues an `sid`. The fail-closed guard rejects an all-zero derived `SessionID` (`sign/sign.go:162`) or an all-zero salt (`sign/sign.go:173`) with `ErrDegenerateSession`, and surfaces a short-read error from `io.ReadFull`. The zero-checks use `isZero32` (`sign/sign.go:250`), a branch-free `subtle.ConstantTimeCompare` against a zero array; the guarded values are not adversary-chosen, but the check is kept uniform. This is the durable fix for the CRIT-1 nonce-reuse leak `(z_sum − Σ s_i·λ_i·c)·u^{-1} = R`; reuse durability no longer rests on an external slot-uniqueness invariant. |
| `sign.DeterministicNonceSource` (`sign/sign.go`) | **(a)** | The KAT/oracle seam: a `KeyedPRNG` over `seed \|\| "corona.sign.nonce-salt.v1" \|\| partyIndex`. Used only by reproducibility harnesses to pin the hedge salt; production never calls it. No secret material (the seed is a test fixture). |

---

## 2. Round-2 masking and the secret-dependent arithmetic

| Location | Status | Notes |
|---|---|---|
| Additive masks (`sign/sign.go:317`, `:323`) | **(a)** | Each `z_i` is masked by `mask = Σ_j PRF(seed_i[j], …)` (outgoing row) minus `maskPrime = Σ_j PRF(seed_j[i], …)` (incoming column), both sums of uniform `R_q` PRF outputs over pairwise seeds (`primitives.PRF`, `primitives/hash.go:173`). The two double-sums telescope to zero when the quorum's `z_i` are summed in `SignFinalize`, so no per-party `c·s` is ever broadcast in the clear (the structural no-leak property). The masking arithmetic (`utils.VectorAdd`/`VectorSub`/`VectorPolyMul`) is coefficient-wise `uint64` ring arithmetic from lattigo — branch-free over the modulus. |
| `s_i·λ_i·c` term (`sign/sign.go:335`–`:340`) | **(a)** | `VectorPolyMul` is NTT-domain Montgomery multiplication on `uint64` coefficient slices (lattigo `MulCoeffsMontgomery*`); no secret-dependent branch. The result is immediately additively masked before it leaves the function. |
| `primitives.PRF` seed expansion (`primitives/hash.go:173`) | **(a) / (TCB)** | The PRF key derivation (suite PRF) is constant-time in its inputs; the subsequent `NewUniformSampler.ReadNew` over the derived stream is the lattigo uniform sampler — see the (TCB) note in §4. |

---

## 3. Share verification, complaints, and digest comparison

| Location | Status | Notes |
|---|---|---|
| `utils.ConstantTimePolyEqual` (`utils/utils.go:29`) | **(a)** | The **single canonical** constant-time poly comparator: scans every level, no early return, per-level `subtle.ConstantTimeCompare` over the little-endian byte view of each `Coeffs[level]`. Both the dkg2 and reshare verification paths delegate here (one implementation, no `dkg2`↔`reshare` dependency). Citation: `crypto/subtle.ConstantTimeCompare` is constant-time over equal-length inputs per `pkg.go.dev/crypto/subtle`. |
| `dkg2.VerifyShareAgainstCommits` (`dkg2/dkg2.go:473`) | **(a)** | Verifies the Pedersen identity `A·NTT(share) + B·NTT(blind) ?= Σ C_{i,k}` slot-by-slot via `utils.ConstantTimePolyEqual` (`dkg2/dkg2.go:537`) with `eq &= …` accumulation. `share`/`blind` are secret, `commits` public; the comparator does not leak which slot first diverged. Structural pre-checks `len(commits) != threshold` (`:485`) and `len(v) != sign.M` (`:489`) branch on public metadata only. This is the direct response to Findings 5/6 of `luxcpp/crypto/corona/RED-DKG-REVIEW.md` (the upstream `dkg/` package short-circuited on first mismatch). |
| `reshare.VerifyShareAgainstCommits` (`reshare/commit.go:126`) | **(a)** | Recipient-side reshare commit check, identical posture to dkg2: `eq &= utils.ConstantTimePolyEqual(lhs[ri], rhs[ri])` (`reshare/commit.go:178`) across all `M` slots, no early return. Previously this path short-circuited; it now uses the canonical constant-time comparator. `lhs` derives from the secret `(share, blind)`, `rhs` is the public commit vector. |
| `dkg2.CommitDigest` / `reshare.CommitDigest` (`reshare/commit.go:203`) | **(a)** | Return `[32]byte`. Cohort-consistency checks compare two `[32]byte` arrays — Go compiles fixed-size array equality to a constant-time SIMD compare on amd64/arm64 (`cmd/compile/internal/walk/compare.go: walkCompareArray`). |
| `reshare.VerifyActivation` (`reshare/activation.go:127`) | **(a)** | `expectedTranscript != localTranscriptHash` (`reshare/activation.go:138`) is `[32]byte` array equality — constant-time as above. The activation cert is fail-closed: a transcript mismatch returns `ErrTranscriptMismatch` and the share is never activated. |
| dkg2 complaint identification / disqualification (`dkg2/complaint.go`) | **(a)** | Operates on public complaint metadata (sender/complainer IDs, public counters). No secret material; all branches are over public values. |

---

## 4. Samplers — the residual TCB axiom

| Location | Status | Notes |
|---|---|---|
| Round-1 discrete-Gaussian sampling `r_star, e_star, R_i, E_i` (`sign/sign.go:179`, `:185`) | **(a) / (TCB)** | Seeded by the secret-derived `skHash` (the nonce-PRNG seed from §1). The samplers are `github.com/luxfi/lattice/v7/ring.NewGaussianSampler` (a fork of `tuneinsight/lattigo/v7`). Lattigo's discrete-Gaussian sampler uses rejection over a SHAKE/BLAKE2-XOF keystream; the rejection *rate* depends on the rejected uniform byte, **not** on the secret seed value, so timing does not correlate with the secret coefficient being produced. **This constant-time property is asserted of the upstream dependency, not mechanically verified in this tree** — it is the principal Corona TCB axiom (mirrored in `TRUSTED-COMPUTING-BASE.md`). Any secret-seeded sampling (Round-1 nonces, dealer key generation) inherits this assumption. |
| `primitives.GaussianHash` sampler (`primitives/hash.go:154`, `:164`) | **(a) / (TCB)** | Same lattigo Gaussian sampler, seeded from the **public** transcript digest + `mu`. Public seed, so even if the sampler leaked timing on its seed it would reveal nothing secret; the (TCB) note applies only to the sampler's internal byte-level behaviour. |
| `primitives.PRF` uniform sampler (`primitives/hash.go:183`) | **(a) / (TCB)** | `NewUniformSampler` over the PRF-derived stream. Uniform sampling is rejection over the modulus; rate depends on rejected bytes, not on the (secret) seed. Public-vs-secret seed varies by caller; the (TCB) note is on the sampler internals. |
| `primitives.LowNormHash` ternary sampler (`primitives/hash.go:239`) | **(a)** | `NewTernarySampler` seeded from the **public** `(A, b̃, h, mu)` transcript. The sampled challenge `c` is public (it is recomputed by every verifier). No secret on this path. |

---

## 5. Verifier paths (public-input, variable-time-tolerant)

| Location | Status | Notes |
|---|---|---|
| `sign.Verify` / `sign.VerifyWithSuite` (`sign/sign.go:381`, `:387`) | **(b)** | Operates on a public signature `(c, z, Δ)` against the public group key `(A, b̃)`. The first failure mode `r.Equal(c, computedC)` (`sign/sign.go:411`) walks coefficient slices and short-circuits — but every operand is publicly derivable from the wire signature. No secret-share material crosses this surface. |
| `sign.CheckL2Norm` (`sign/sign.go:422`) | **(b)** | Sums `big.Int` squares of the centered `(Δ, z)` coefficients and compares to `Bsquare`. `big.Int.Cmp/Mul/Sub` are **not** constant-time, and the `coeff.Cmp(halfQ) > 0` centering branch is data-dependent — but `(z, Δ)` are the *published* signature components, fully public. The norm bound is a property of public data; leaking timing about it reveals only what the signature bytes already do. The function deliberately logs no intermediates (a log would create a side-channel for log-indexing monitors). |
| `sign.FullRankCheck` (`sign/sign.go:467`) | **(b)** | Gaussian elimination mod `q` over the per-coefficient submatrices of `DSum` to reject a rank-deficient aggregate commitment. `DSum = Σ_j D_j` is the **public** sum of all parties' broadcast Round-1 `D_j` matrices (each `D_j` is broadcast and MAC-bound in Round 1), so every operand is public. `utils.GaussianEliminationModQ` uses `big.Int` and a data-dependent pivot search — variable-time, but only on public aggregate data. Not a secret leak. |

---

## 6. Key-share zeroization

| Location | Status | Notes |
|---|---|---|
| `reshare.EraseShare` (`reshare/keyshare.go:158`) | **(a)** | `for k := range coeffs { coeffs[k] = 0 }` (`reshare/keyshare.go:166`) overwrites the `SkShare` coefficient backing arrays in place after activation. The goal is overwrite-on-deactivation, not constant-time equality; the data is already secret to the local process. |
| `keyera` standard-form secret zeroization (`keyera/keyera.go:255`, `:504`) | **(a)** | After Shamir sharing / resharing, the dealer's or party's standard-form secret copy is zeroed coefficient-by-coefficient. `keyera.Reshare` (`keyera/keyera.go:282`) recombines via a `big.Int` Lagrange linear combination of secret share values with public coefficients — `big.Int` is not constant-time, but every value is held by the **local** party only; there is no remote oracle on the recombination path. `BootstrapPedersen` (`keyera/bootstrap_pedersen.go:144`) is the default since no party ever holds the full master secret; its per-party arithmetic inherits the dkg2 §3 analysis. The legacy trusted-dealer path (`bootstrapTrustedDealerImpl`, `keyera/keyera.go:195`) runs the master secret in `big.Int` on a single dealer machine during a one-time ceremony — timing observable only to the dealer. |

---

## (c) entries

**None.** All reviewed paths land in (a), (b), or the §4 (TCB) axiom.

The (b) entries (`sign.Verify`, `CheckL2Norm`, `FullRankCheck`) are all
public-input verifier paths: `big.Int` and `r.Equal` variable-time
behaviour operates exclusively on the published signature, the public
group key, or the broadcast aggregate `DSum`. Promoting them to
constant-time would add cost for no confidentiality gain.

The single (TCB) axiom (§4) is the lattigo Gaussian / uniform sampler
constant-time behaviour for **secret-seeded** Round-1 nonce and dealer
sampling. It is asserted from the upstream construction (rejection rate
depends on rejected bytes, not the secret seed), not mechanically proven
in this tree. Discharging it (e.g. a `dudect` measurement of the sampler
under fixed-vs-random secret seeds, or a Jasmin `#ct`-checked sampler) is
tracked as a v0.8.0 high-assurance gate.

---

## Cross-references

- TCB axiom inventory: `TRUSTED-COMPUTING-BASE.md`, `AXIOM-INVENTORY.md`.
- Nonce-key construction and the CRIT-1 history: `primitives/hash.go`
  (`DeriveSessionID`, `PRNGKeyForRound`) and `sign/sign.go`
  (`SignRound1`).
- Constant-time share comparison origin:
  `luxcpp/crypto/corona/RED-DKG-REVIEW.md` Findings 5/6.
