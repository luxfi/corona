# Corona — TEE Integration (proposed)

> Companion to `DEPLOYMENT-RUNBOOK.md §Operational mitigations item 5`
> ("TEE attestation, recommended"). This document specifies the
> attestation boundary, key-isolation contract, and the per-platform
> integration shape — without complecting any of this with the
> Corona cryptographic core.

**Decomplecting rule (load-bearing).** TEE attestation is a single
*layer* sitting outside the cryptographic math:

```
+--------------------------------------------------------------+
| operator policy: which TEE? which key-release predicate?      |  policy
+--------------------------------------------------------------+
| attestation: evidence -> verifier -> bool                     |  trust
+--------------------------------------------------------------+
| share storage / signing: sealed share -> Round1/Round2/Final  |  crypto
+--------------------------------------------------------------+
| Corona kernel: 2-round Module-LWE signing                     |  math
+--------------------------------------------------------------+
```

The Corona kernel (`sign/`, `threshold/`, `dkg2/`, `reshare/`) MUST
NOT depend on, link against, or branch on TEE state. The TEE layer
is **only** consulted at three lifecycle moments:

1. **Bootstrap-trusted-dealer ceremony**: caller of
   `keyera.BootstrapTrustedDealer` decides whether to run inside a
   TEE. Corona observes the result via the standard
   `BootstrapTranscript` — no API change.
2. **Per-validator share storage**: each validator's `KeyShare`
   bytes are sealed under a TEE-bound key. Corona observes the
   share via the standard `KeyShare` struct — no API change.
3. **Per-validator signing session**: `Round1`, `Round2`, and
   `Finalize` execute inside the TEE. Corona observes the signing
   protocol via the standard `(D, MACs)`, `Z`, `Signature` byte
   structures — no API change.

There is no `corona.AttestationVerifier` interface, no
`corona.WithTEE(...)` option, no TEE-specific build tag. The
TEE layer is an *operator's deployment concern* and is wired
above Corona via the consensus layer's validator-bootstrap
plumbing.

---

## §1 Threat model addition

In `docs/mptc/threat-model.md §9.2 "Out of scope at this submission"`,
the following items are flagged as **deployment-layer-mitigated** via
TEE:

- Cache-timing side channels
- Power side channels
- EM side channels
- Aggregator-host compromise during signing session
  (`DEPLOYMENT-RUNBOOK.md §Trust-model disclosure item 2`)

The TEE integration layer brings these from "not addressed" to
"addressed under the TCB of {SGX, SEV-SNP, TDX, NVIDIA-CC, Apple-SEP}",
with the following residual assumption surface:

| Assumption | What we trust |
|---|---|
| TEE vendor firmware | The CPU/GPU vendor's microcode, BIOS, and signed bootloader. |
| TEE attestation root | The vendor's attestation signing key (Intel IAS, AMD KDS, NVIDIA NRAS, Apple AAS). |
| Reproducible build | The `luxfi/corona` binary measured into the attestation report matches a publicly-published Git SHA at a tagged release. |
| TEE side-channel resistance | The TEE's own side-channel posture — bounded by the public CVE record of the chosen platform (e.g., SGX has a long history of micro-architectural side-channel attacks; SEV-SNP and TDX are more recent). |

The TEE layer trades a TCB inclusion (vendor microcode + attestation
root) for closure of the OS-kernel-compromise and side-channel
threats. Operators MUST evaluate whether this trade is acceptable
for their specific deployment.

## §2 Reproducible build contract

Every Corona release tag (`v0.7.x`) ships:

1. **Source SHA**: the Git SHA of the release commit.
2. **`scripts/build.sh` invocation**: produces the binary
   `bin/corona` from the release commit.
3. **Reference-measure manifest**: SHA-256 of `bin/corona` produced
   on a pinned builder (`golang:1.26.4-alpine` per `Dockerfile`).
4. **Cross-runtime byte-equality**: `scripts/regen-kats.sh --verify`
   against the C++ port at `~/work/luxcpp/crypto/corona/`.

The TEE attestation verifier consumes (1) + (3) and rejects any
report whose measurement does not match the published manifest. The
manifest is published at `https://lux.network/release/corona/v0.7.x/manifest.json`
and signed by the foundation release key.

> **Roadmap (v0.7.6)**: pin the `golang:1.26.4-alpine` builder image
> by digest, not tag, so the reference measure is reproducible
> against a specific OCI image digest.

## §3 Per-platform integration

### §3.1 AMD SEV-SNP (Linux validators)

**Status**: recommended primary path for Linux validators.

**Boundary**: full VM-level confidentiality. The Corona validator
process runs inside a SEV-SNP-protected VM ("CVM"). The
hypervisor sees encrypted memory; the host kernel cannot read
guest pages.

**Attestation flow**:

1. CVM boot loads OVMF -> Linux kernel -> `cosi-cvm-agent` (the
   Lux CVM bootstrap agent; lives in `~/work/lux/cosi-cvm-agent`).
2. Agent calls `SNP_GET_REPORT` ioctl to obtain a SEV-SNP
   attestation report binding the in-memory `(measurement,
   report_data)`. `report_data` is the SHA-256 of the
   validator-bound `report_nonce` (received from the registration
   service on first contact).
3. Agent posts the report to the consensus layer's TEE-registration
   endpoint. The endpoint verifies the report against AMD's KDS
   (Key Distribution Service) using the chip's VCEK certificate,
   confirms `measurement` matches the published `bin/corona`
   manifest, and accepts the validator.
4. On accept, the consensus layer releases the validator's
   pre-sealed `KeyShare` (encrypted under a key derived from the
   attestation transcript) to the agent.
5. Agent unseals into the SEV-SNP-protected memory; Corona's
   `threshold.NewSigner` operates on the unsealed share.

**Key isolation**: the SEV-SNP VM memory is encrypted by the
PSP-bound C-bit memory encryption. The unsealed share is never
visible to the hypervisor or the host kernel.

**Side channels addressed**: cold-boot, DMA-based read of guest
memory, hypervisor-introspection, and (under SEV-SNP integrity
protection, not SEV-ES) RowHammer and Spectre-class transient
attacks from the host.

**Residual risks**: SEV-SNP's own published CVE record (e.g.,
CVE-2023-20593 "Zenbleed", CVE-2024-3315 "SmmCallout"). Operators
MUST apply microcode patches.

**Code touchpoint**: zero. Corona's `KeyShare` bytes are unsealed
by the agent and handed to `threshold.NewSigner` via the standard
Go struct.

### §3.2 NVIDIA Confidential Computing (H100/H200/B200 CC mode)

**Status**: recommended when GPU-accelerated NTT/Montgomery is
used in production. Corona's `gpu` package opts the lattice NTT
dispatch into the GPU at validator setup time; the GPU itself
becomes part of the validator's TCB. **Confidential Computing**
mode on H100/H200/B200 puts the GPU into an attestable
confidential mode where the host CPU cannot read GPU memory.

**Boundary**: a CVM (SEV-SNP or TDX) is paired with a CC-mode
GPU. The PCIe link is encrypted via SPDM (Security Protocol and
Data Model) session keys. The GPU's HBM memory is protected by
the GPU's own confidential-mode firmware.

**Attestation flow**:

1. CVM boot (per §3.1 or §3.3).
2. CVM-to-GPU SPDM session is established. The GPU produces a
   **device attestation report** signed by the NRAS (NVIDIA Remote
   Attestation Service) root.
3. Agent verifies the GPU report via NRAS, confirms the GPU
   firmware version + CC-mode active.
4. Composite attestation: agent emits `evidence = SNP_report ||
   NRAS_GPU_report || binding_nonce`. The consensus-layer verifier
   checks both reports and the binding.
5. Corona's `gpu.UseAccelerator()` is called inside the CVM after
   composite attestation passes. The lattice GPU NTT dispatch
   runs over the encrypted PCIe link to the CC-mode GPU.

**Key isolation**: secret shares never leave the CVM's encrypted
memory. The data sent to the GPU for NTT computation is the
*coefficient vector after Montgomery encoding* — the secret-share
material is mixed in earlier (in CPU code) and the GPU NTT operates
on values that are blinded by the per-session mask `R` (Round 1)
and the public matrix `A` (Round 2). The GPU sees no clear-text
share.

> **HONEST GAP**: the precise blinding analysis ("what does the GPU
> see, formally?") for the CC-mode dispatch is an open
> question for the v0.8.0 cryptographic audit. Until that audit
> completes, deploying Corona under CC-mode GPU is APPROVED with
> the caveat that the GPU is part of the TCB; operators MUST
> evaluate whether they trust NVIDIA's CC-mode firmware + NRAS
> attestation.

**Side channels addressed**: PCIe sniffing, host-DMA-into-GPU-memory,
GPU-firmware-from-host introspection.

**Residual risks**: NVIDIA CC-mode CVE record (e.g., GPU-resident
side-channels in shared-memory paths — none publicly disclosed as
of 2026-06-01, but the platform is recent).

**Code touchpoint**: zero in `corona/sign`, `corona/threshold`. One
plumbing change in `corona/gpu/gpu.go::MaybeRegister` to optionally
gate registration on a "confidential-mode-attested" flag passed at
context-init time. **Proposed (not yet implemented)**:

```go
// MaybeRegisterAttested is the CC-mode variant of MaybeRegister.
// It registers the ring only if the supplied attestation token
// passes the consensus-layer's attestation verifier.
//
// On nil token the call falls through to plain MaybeRegister
// (preserves the existing API contract).
func MaybeRegisterAttested(r *ring.Ring, attestation []byte) error {
    if attestation == nil {
        MaybeRegister(r)
        return nil
    }
    if !attestation_verifier.Verify(attestation) {
        return ErrAttestationRejected
    }
    return RegisterRing(r)
}
```

The `attestation_verifier` package would live OUTSIDE `corona/` —
in the consensus layer at `~/work/lux/threshold/attestation/` or
similar. Corona just consumes the bool.

### §3.3 Intel TDX (alternative Linux path)

**Status**: alternative to §3.1 for Intel platforms. Substantively
equivalent boundary (VM-level confidentiality, attestation via
Intel TDX Provisioning Certification Service).

**Attestation flow**: analogous to §3.1, replacing `SNP_GET_REPORT`
with `TDG.MR.REPORT` and replacing AMD KDS with Intel PCCS / TGS.

**Composite with NVIDIA CC**: TDX + H100 CC is a supported
deployment configuration per NVIDIA's CC documentation.

### §3.4 Apple Secure Enclave (validator share storage on
Apple Silicon)

**Status**: recommended for Apple Silicon validators where the
SEP-bound key is used to seal the at-rest `KeyShare`.

**Boundary**: the SEP is a separate ARM core inside the M-series
SoC with its own bootloader, kernel, and tamper-resistant key
storage. SEP-bound keys are non-extractable and gated by
SecureEnclave biometric / passcode policy.

**Attestation flow** (limited compared to SEV-SNP):

1. Validator process generates a per-validator long-term key
   via `Security.framework` `SecKeyCreateRandomKey` with
   `kSecAttrTokenIDSecureEnclave`. The private key never leaves
   the SEP.
2. The KeyShare bytes are wrapped under an AES-256-GCM key whose
   master key is derived from a `SecKeyCreateRandomKey`-backed
   ECC P-256 key in the SEP. Decryption requires the SEP to
   sign a challenge under the SEP-bound private key.
3. There is NO ATTESTATION REPORT comparable to SEV-SNP/TDX/CC —
   Apple does NOT publish a remote-attestation root for the SEP.
   Validators using SEP-bound storage cannot prove to the chain
   that their share is SEP-sealed; this is a **local-only**
   defense-in-depth measure.

**Key isolation**: at-rest share material is sealed under a
non-extractable SEP key. A non-root attacker on the macOS host
cannot extract the share without unlocking the SEP via the
`LAContext.evaluatePolicy` biometric/passcode flow.

**Side channels addressed**: cold-boot, disk-image-exfiltration,
non-root userland processes reading the validator's share file.

**NOT addressed**: a root-equivalent attacker on the macOS host
who calls `Security.framework` after the SEP unlocks (because
SEP unlock policy delegates to the host OS for biometric
evaluation). For full host-isolation on Apple Silicon, run the
validator inside a `virtio-fs`-backed Linux VM under Apple's
`Virtualization.framework` and use the Linux VM's SEV-SNP-style
attestation (not available natively; future work).

**Code touchpoint**: zero in `corona/`. The Apple SEP wrapping
lives in `~/work/lux/threshold/storage/sep-darwin.go` (or
analogous) at the storage layer. Corona's `KeyShare` is loaded
via the storage layer's `LoadShare()` API which returns the
unwrapped `KeyShare` struct.

### §3.5 Intel SGX (deprecated for Corona)

**Status**: NOT recommended. Intel SGX has a long published CVE
record of micro-architectural side-channel attacks (Foreshadow,
ZombieLoad, LVI, ÆPIC Leak). Corona's Module-LWE arithmetic spends
significant time on `lattigo`'s NTT and Gaussian sampling — both
data-dependent paths that have been demonstrated vulnerable to
side-channel extraction on SGX in the published literature.

SGX is supported in the *attestation-layer interface* (the
consensus-layer verifier accepts SGX EPID/DCAP reports), but the
**Corona reference deployment guidance** in
`DEPLOYMENT-RUNBOOK.md` explicitly prefers SEV-SNP / TDX / CC-mode
over SGX.

## §4 Composite attestation evidence

The consensus-layer registration endpoint accepts a single composite
attestation evidence bundle for any combination of:

- **CPU side**: SEV-SNP report OR TDX report OR (SGX report,
  not recommended).
- **GPU side**: NRAS attestation report (optional; required only
  if `gpu.UseAccelerator()` is invoked).
- **Storage side**: SEP-bound key witness (Apple-only;
  defense-in-depth, no remote-attestation).

The composite is bound by:

```
binding_nonce = SHA-256( "corona-tee-bind-v1" ||
                          validator_id ||
                          group_id ||
                          era_id ||
                          challenge_nonce )
```

where `challenge_nonce` is fresh per-registration randomness from
the consensus layer. Each platform-specific report embeds
`binding_nonce` in its `report_data` field. The verifier checks
all reports, confirms binding-nonce consistency, and accepts the
validator on success.

## §5 Key release predicate

The pre-sealed `KeyShare` at the consensus-layer registration
service is encrypted under a key derived from the attestation
transcript. **The key release predicate** is:

```
release_key = HKDF-SHA-256(
    salt   = "corona-share-release-v1",
    ikm    = composite_attestation_transcript,
    info   = validator_id || group_id || era_id,
    length = 32,
)
```

The consensus-layer registration service computes this key only on
successful composite-attestation verification. The registration
service then unwraps the validator's `KeyShare` under this key and
delivers the wrapped bytes to the attesting validator.

**This is the policy gate.** Without a passing attestation, no
key release. Without a key release, no Round 1 / Round 2 / Final.

## §6 Honest non-claims

- Corona does NOT today ship `~/work/lux/threshold/attestation/`.
  That package is a **proposed** addition for the v0.7.6 / v0.8.0
  roadmap; this document specifies its API surface.
- Corona does NOT today ship `MaybeRegisterAttested` in `gpu/`.
  Same roadmap.
- Apple SEP integration is **local-only** — no remote attestation
  is possible against Apple's platform. Operators relying on
  Apple-Silicon validators MUST accept this as a defense-in-depth
  measure, not a primary trust anchor.
- The "what does the CC-mode GPU see, formally?" blinding analysis
  for §3.2 is an OPEN audit item for v0.8.0.

## §7 Roadmap

| Item | Target | Owner |
|---|---|---|
| `attestation_verifier` package at `~/work/lux/threshold/attestation/` | v0.7.6 | consensus team |
| `MaybeRegisterAttested` in `gpu/gpu.go` | v0.7.6 | corona |
| SEV-SNP CVM bootstrap agent at `~/work/lux/cosi-cvm-agent` | v0.7.6 | infra |
| Reference docker-compose for "validator + SEV-SNP CVM + H100 CC" | v0.8.0 | infra |
| Apple SEP storage layer at `~/work/lux/threshold/storage/sep-darwin.go` | v0.8.0 | apple-silicon track |
| Formal blinding analysis for CC-mode GPU (NTT inputs/outputs) | v0.8.0 | external audit (GATE-4) |
| Reproducible builder image pinned by digest | v0.7.6 | release |

---

**Document metadata**

- Name: `docs/mptc/tee-integration.md`
- Version: v0.1 (initial TEE integration spec)
- Date: 2026-06-02
- Companion to: `DEPLOYMENT-RUNBOOK.md §Operational mitigations item 5`,
  `docs/mptc/threat-model.md §9.2`
- Status: proposed; no Corona code change required for §3.1, §3.3, §3.4.
  §3.2 adds one optional plumbing function (`MaybeRegisterAttested`)
  at the next minor version.
