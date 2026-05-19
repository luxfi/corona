# Corona dudect constant-time harness

Statistical CT validation for Corona's threshold path, mirroring
~/work/lux/pulsar/ct/dudect/.

## What's here

| File | Purpose |
|---|---|
| `verify_ct.go` | cgo bridge: corona threshold.Verify |
| `combine_ct.go` | cgo bridge: corona threshold Signer.Finalize (Combine) |
| `dudect_verify.c` | dudect main loop driving Verify |
| `dudect_combine.c` | dudect main loop driving Combine |
| `dudect_compat.h` | AArch64 compat shim for x86 intrinsics |
| `Makefile` | build verify + combine binaries |
| `fetch.sh` | clone upstream dudect at the pinned commit |

## Build + run

```bash
./fetch.sh             # first time only -- clones dudect
make                   # builds dudect_verify + dudect_combine
./dudect_verify        # smoke test (10000 samples/batch * 4 batches)
./dudect_combine       # smoke test (2000 samples/batch * 4 batches)
```

## Submission run

```bash
# 10^9 samples per target on a pinned-CPU quiet host:
DUDECT_SAMPLES=1000000 DUDECT_MAX_BATCHES=1000 ./dudect_verify
DUDECT_SAMPLES=1000000 DUDECT_MAX_BATCHES=1000 ./dudect_combine
```

## CT-population framing

Both harnesses use the **valid-signature class** framing:

- **Verify**: both class A and class B are valid Corona signatures on
  the same (group_pk, message). They differ only in the per-signing
  rejection-loop randomness. Any timing difference detected is a
  signature-content-dependent code path in Verify.
- **Combine**: both class A and class B are valid R2-data tuples. The
  Combine path has NO secret inputs (every input is broadcast on the
  wire), so any timing difference is an unexpected content-dependent
  code path in Finalize.

The valid-class framing differs from the simpler garbage-bytes-vs-
random-bytes pattern because Corona Verify has no secret state to
leak; the empirically meaningful CT property is the valid-population
constancy.

## Hosts

- x86_64 Linux/macOS: builds against upstream dudect.h directly.
- aarch64 Linux/macOS: `dudect_compat.h` is force-included to supply
  AArch64 cycle-counter equivalents (CNTVCT_EL0 on Linux,
  `mach_absolute_time()` on Darwin).

## Limitations

- 10000-sample smoke runs are NOT statistically meaningful for CT
  certification. The smoke-test pass is "the harness compiles and runs
  without obvious leakage signal." The submission-grade verdict
  requires the full 10^9-sample run on pinned, quiet hardware.
- Combine's CT property is trivially true (no secret inputs); the
  Combine harness is a SANITY CHECK on the Finalize pipeline, not a
  property test.

## Refinement

The dudect harnesses provide EMPIRICAL CT evidence for the modules:

- `Verify`: corona/threshold/threshold.go:Verify + corona/sign/sign.go:Verify
- `Combine`: corona/threshold/threshold.go:Signer.Finalize + corona/sign/sign.go:SignFinalize

The Jasmin-CT theoretical CT proof for the threshold layer is in
`~/work/lux/corona/jasmin/threshold/{round1,round2,combine}.jazz` and
`scripts/checks/jasmin.sh` enforces it as a per-push blocking gate.
