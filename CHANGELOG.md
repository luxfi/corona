# pulsar CHANGELOG

Notable changes to the `pulsar` module. Pre-release; semantic versioning
applied per PHILOSOPHY.md (patch only — never minor/major without explicit
approval).

## Unreleased

### Breaking — F22 hash-suite injection into Sign

`pulsar/primitives/hash.go` no longer hardcodes `blake3.New()`. Every
Sign-path primitive now takes a `hash.HashSuite` as its first argument:

```
PRNGKey(suite, skShare)                       // was PRNGKey(skShare)
PRNGKeyForRound(suite, skShare, sid)          // was PRNGKeyForRound(skShare, sid)
GenerateMAC(suite, TildeD, MACKey, ...)       // was GenerateMAC(TildeD, MACKey, ...)
GaussianHash(suite, r, hash, mu, sigma, ...)  // was GaussianHash(r, hash, mu, sigma, ...)
PRF(suite, r, sd_ij, key, mu, hash, n)        // was PRF(r, sd_ij, key, mu, hash, n)
Hash(suite, A, b, D, sid, T)                  // was Hash(A, b, D, sid, T)
LowNormHash(suite, r, A, b, h, mu, kappa)     // was LowNormHash(r, A, b, h, mu, kappa)
```

`suite == nil` resolves to the production default, `Pulsar-SHA3`
(cSHAKE256 / KMAC256 / TupleHash256 per FIPS 202 + NIST SP 800-185).
The legacy `Pulsar-BLAKE3` suite remains available via
`hash.NewPulsarBLAKE3()` for cross-port byte checks.

`sign.Party` gains a `Suite hash.HashSuite` field, defaulted by
`NewParty` to `hash.Default()`. Operators can construct with an explicit
suite via `NewPartyWithSuite(id, r, rXi, rNu, sampler, suite)`. The free
function `sign.Verify(...)` keeps its previous signature and now resolves
to the production default internally; the suite-explicit form is
`sign.VerifyWithSuite(suite, ...)`.

This closes the gap where the HIP-0077 claim that Pulsar uses SHA-3
cSHAKE256/KMAC256/TupleHash256 in production was structurally false at
the Sign layer (only `pulsar/reshare/`, `pulsar/dkg2/`, `pulsar/keyera/`
were consuming `pulsar/hash/HashSuite` previously).

### Follow-up — KAT regeneration

The historical BLAKE3 KAT transcripts emitted by
`cmd/corona_oracle_v2` were computed against the previous raw
`blake3.New()` framing in `primitives/hash.go`. After this refactor, the
oracle still emits under `pulsarhash.NewPulsarBLAKE3()`, but the framing
now includes the suite's customization tags (`PULSAR-HC-v1`,
`PULSAR-HU-v1`, `PULSAR-PRF-v1`, etc.) and length-prefixing, so the
emitted bytes no longer byte-match pre-refactor JSON.

The Pulsar-SHA3 production KATs are not yet emitted. Both lie outside
the scope of this PR:

- Regenerate the legacy BLAKE3 oracle JSON
  (`go run ./cmd/corona_oracle_v2 emit --out ./test/kats/blake3`)
  and cross-validate with the C++ port.
- Land a parallel `cmd/corona_oracle_v3` (or `--suite` flag) that
  emits Pulsar-SHA3 KATs under `./test/kats/sha3/` and pin them as the
  normative reference for downstream ports.

The skipped test `TestKATsRegenerated` in
`primitives/hash_test.go` is the placeholder guard.
