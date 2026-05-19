# Corona Jasmin sources

Constant-time threshold layer + centralized R-LWE Sign reference,
written in Jasmin (https://github.com/jasmin-lang/jasmin) for
jasmin-ct verification + EasyCrypt extraction.

## Layout

```
jasmin/
  lib/                  -- Shared primitives (corona_params, seed,
                           transcript, mac, lagrange).
  rlwe/                 -- Centralized R-LWE Sign (single-party).
  threshold/            -- Threshold round1.jazz, round2.jazz,
                           combine.jazz.
```

## Compile / verify

Type-check:
```bash
jasminc -until_typing threshold/round1.jazz
jasminc -until_typing threshold/round2.jazz
jasminc -until_typing threshold/combine.jazz
```

Constant-time check:
```bash
jasmin-ct threshold/round1.jazz
jasmin-ct threshold/round2.jazz
jasmin-ct threshold/combine.jazz
```

The threshold-layer files are BLOCKING gates in `scripts/checks/jasmin.sh`.

## Status

v0.7.0 ships the **structural sources**. Each file mirrors its
luxfi/corona/sign/sign.go reference body, marked with #ct annotations
at the export boundaries. The libjade-NTT kernel calls are sketched at
the structural level; full body wiring is the production target for
external audit at v0.8.0.

The skeleton is sufficient for:
- jasminc type-checking (the #ct annotations are syntactically valid)
- jasmin-ct CT analysis (the secret-data flow boundaries are pinned)
- EasyCrypt extraction sanity (the export ABI matches the wrapper layer)

The full body wiring is the path to closing the byte-walk axioms in
`proofs/easycrypt/Corona_N1_{Combine,Sign}_Refinement.ec`.

## CT annotations

Each export function carries a `#[ct = ...]` annotation declaring the
public/secret level of each argument. The CT type is:
```
pointer-value-public * ... -> return-public
```

Pointed-to data carries its own secrecy level inside the function via
`#secret` / `#public` markers on stack arrays. The wrapper layer in
the Go reference (luxfi/corona/sign/sign.go) ensures the pointer
contents satisfy these annotations.

## Refinement target

Each .jazz file refines a corresponding Go function in luxfi/corona/sign/sign.go:

| Jasmin | Go reference |
|---|---|
| `threshold/round1.jazz` | `Party.SignRound1` |
| `threshold/round2.jazz` | `Party.SignRound2` + `Party.SignRound2Preprocess` |
| `threshold/combine.jazz` | `Party.SignFinalize` |
| `rlwe/sign.jazz` | A centralized aggregator running all three rounds with #parties=1 |
| `lib/lagrange.jinc` | `primitives.ComputeLagrangeCoefficients` |
| `lib/transcript.jinc` | `primitives.Hash` (transcript_hash) |
| `lib/mac.jinc` | `primitives.GenerateMAC` |
| `lib/seed.jinc` | `primitives.PRNGKeyForRound` |
