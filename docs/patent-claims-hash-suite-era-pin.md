# Hash-Suite-Pinned KeyEra — Patent Claim Drafts (Attorney Review)

> **Internal working document.** Bundle #17 of the Lux PATENT-INVENTORY.
> Not a filed application; not a legal opinion.

## §0 Bundle summary

- **Title**: A hash-suite-pinned key-era abstraction for blockchain
  threshold cryptography in which the SP 800-185 hash function
  (KMAC, cSHAKE, TupleHash) used for challenge derivation,
  envelope binding, and Lagrange reconstruction is recorded
  immutably at key-era bootstrap and remains unchanged through
  every share-redistribution operation within the era; only a
  governance-gated reanchor opens a new era and permits a
  hash-suite change.
- **Inventors**: Lux Industries cryptography team.
- **Priority date**: file as US provisional within 12 months OR
  defensive publication.
- **Estimated claim count**: 9 (1 independent + 8 dependent).
- **Defensive-vs-offensive**: **Defensive.** Recommend defensive
  publication.

## §1 Background and prior art

1. **NIST SP 800-185** (cSHAKE, KMAC, TupleHash, 2016): hash
   function family for domain-separated cryptographic use.
2. **NIST FIPS 204 ML-DSA-65** (2024): fixed SHAKE256-based hash
   suite per spec.
3. **NIST FIPS 205 SLH-DSA** (2024): hash-suite-parametric (SHA2
   vs SHAKE variants).
4. **TLS 1.3 cipher-suite negotiation** (RFC 8446): per-session
   suite agreement; not era-pinned.

Lux's contribution: the hash-suite identifier is **era-pinned** at
bootstrap. A reshare cannot change it. Only the rare reanchor
event (a fresh key era) admits a change. This invariant prevents
"hash-suite migration in mid-flight" attacks where an adversary
attempting to substitute a weaker hash function during reshare
could create cross-era signature collisions.

## §2 Inventive concept

```
type HashSuite struct {
    ID   HashSuiteID            // wire-byte enum
    XOF  cSHAKE / KMAC256 / ...
    Tag  string                 // customization tag
}

type KeyEra struct {
    EraID       uint64
    HashSuite   HashSuite       // PINNED — immutable in era
    GroupKey    GroupKey
    Shares      []Share
}

Bootstrap(committee, threshold, hashSuite) -> KeyEra
  // records hashSuite immutably
Reshare(era, newCommittee) -> Shares'
  // CANNOT change era.HashSuite
Reanchor(committee, threshold, hashSuite') -> KeyEra'
  // opens new era; hashSuite' may differ
```

## §3 Independent claim (draft)

> **Claim 1.** A computer-implemented method for managing
> cryptographic hash-suite selection across a blockchain threshold
> key-era lifecycle, the method comprising:
>
> (a) defining a hash-suite identifier enumeration with at least
>     two distinct identifiers naming distinct SP 800-185 hash
>     functions (e.g., a `cSHAKE256` identifier and a `KMAC256`
>     identifier), each identifier additionally specifying a
>     fixed customization tag;
>
> (b) at chain genesis or at a rare governance-gated reanchor
>     event, opening a new key era by recording in the chain
>     state a 3-tuple `(EraID, HashSuiteID, GroupKey)` where the
>     `HashSuiteID` is selected at that time and bound into the
>     era's identity hash;
>
> (c) at every share-redistribution event within the era —
>     including HJKY97 share refresh and Wong-Wang-Wing share
>     redistribution events — refusing to change the era's
>     `HashSuiteID`, with any attempted change causing the share
>     redistribution to fail with a typed
>     `ErrHashSuiteMismatch` error;
>
> (d) using the era's `HashSuiteID` to instantiate the hash
>     function used for: (i) challenge derivation in threshold
>     signing, (ii) DKG envelope binding, (iii) Lagrange-
>     interpolation transcript hashing, and (iv) any other
>     hash-dependent operation within the era; and
>
> (e) at any subsequent reanchor event, opening a new era with a
>     new `EraID`, optionally a new `HashSuiteID`, and a new
>     `GroupKey`, with the previous era archived for historical
>     verification.

## §4 Dependent claims (drafts)

**Claim 2.** The method of claim 1, wherein the hash-suite
identifier enumeration further includes a `BLAKE3` identifier
naming the BLAKE3 hash function with a domain-separated
customization tag.

**Claim 3.** The method of claim 1, wherein the era's
`HashSuiteID` is bound into every signature emitted under the
era's `GroupKey` via the cSHAKE256 customization parameter
applied to the signature's challenge derivation, providing
cryptographic (not just protocol-level) hash-suite binding.

**Claim 4.** The method of claim 1, wherein the chain state
records, for each era, the era's `HashSuiteID` in the validator-
set Merkle root field of the era's chain configuration,
allowing verifiers to obtain the era's hash suite from chain
state without out-of-band agreement.

**Claim 5.** The method of claim 1, wherein the reanchor event
of step (e) requires a supermajority of the current committee
plus a time-locked delay to commit, preventing unauthorized
era rotation.

**Claim 6.** The method of claim 1, wherein the prior era's
`HashSuiteID` is preserved in chain state so that historical
signatures emitted under the prior era's hash suite remain
verifiable after a reanchor.

**Claim 7.** The method of claim 1, wherein the method is
implemented in a blockchain threshold signing kernel selected
from: a Module-Lattice kernel (Pulsar / FIPS 204 ML-DSA-65),
a Ring-Lattice kernel (Corona / Boschini), or a hash-based
kernel (Magnetar / FIPS 205 SLH-DSA), with the same hash-suite
era-pin invariant applied uniformly across kernels.

**Claim 8.** The method of claim 1, wherein the
`ErrHashSuiteMismatch` typed error is propagated through the
chain's `ChainConfig.IsStrictPQ` profile gating, allowing
chains operating under strict-post-quantum profiles to
additionally refuse any non-PQ-approved hash-suite identifier.

**Claim 9.** A non-transitory computer-readable medium storing
the Go source code of the `HashSuiteID` enumeration, the
`HashSuite` struct, the `KeyEra` struct, the `Bootstrap`,
`Reshare`, and `Reanchor` operations, and the
`ErrHashSuiteMismatch` typed error.

## §5 Reference to implementation

- `~/work/lux/corona/hash/sp800_185.go` (Corona-SHA3 / KMAC).
- `~/work/lux/corona/keyera/keyera.go` (KeyEra struct).
- `~/work/lux/pulsar/proofs/hash-suite-separation.tex`
  (formal era-pinning argument).
- `~/work/lux/lens/keyera/` (curve sibling, same invariant).

## §6 Defensive vs offensive

**DEFENSIVE.** This is a sensible invariant but more of a protocol-
hygiene choice than a hard technical invention. Recommend
defensive publication.

---

**Document metadata**
- Path: `corona/docs/patent-claims-hash-suite-era-pin.md`
- Bundle: #17 of `lps/PATENT-INVENTORY.md`
- Created: 2026-05-19
