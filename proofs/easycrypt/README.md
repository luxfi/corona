# Corona EasyCrypt Theories

This directory holds the EasyCrypt mechanization of the Class N1
(byte-equality) and Class N4 (reshare public-key preservation)
correctness claims for Corona, mirroring `~/work/lux/pulsar/proofs/easycrypt/`.

## File map

| File | Contains |
|---|---|
| `Corona_N1.ec` | Master theorem: threshold output = single-party output (byte-equal) on the reconstructed share |
| `Corona_N4.ec` | Reshare public-key preservation on the honest reshare module |
| `Corona_N1_Memory.ec` | byte-memory model (mem_t + load/store + frame laws) |
| `Corona_N1_Signature_Codec.ec` | Corona signature type + codec round-trip + length |
| `Corona_N1_Combine_Layout.ec` | Combine input/output byte layout invariants |
| `Corona_N1_Sign_Layout.ec` | centralized Sign input/output byte layout invariants |
| `Corona_N1_Combine_Refinement.ec` | byte-walk + memory-sep + layout-frame axioms for the extracted Combine |
| `Corona_N1_Sign_Refinement.ec` | byte-walk + memory-sep + layout-frame axioms for the extracted Sign |
| `Corona_N1_Combine_Wrapper.ec` | wrapper bridge: extracted Combine -> Corona_Threshold module interface |
| `Corona_N1_Sign_Wrapper.ec` | wrapper bridge: extracted Sign -> RLWESign module interface |
| `Corona_N1_Extracted.ec` | the IMPLEMENTATION-BACKED end-to-end theorem; cite this |
| `lemmas/RLWE_Functional.ec` | in-house EC mechanization of Boschini ePrint 2024/1113 §3 Sign |
| `lemmas/Corona_CT.ec` | constant-time obligations on the threshold-layer routines |

Total: 13 EC files, mirroring Pulsar's exact count.

## Admit budget

0 admits across all files. Tracked by
`scripts/checks/ec-admits.sh` (ADMIT_BUDGET=0).

## Trust footprint

The IMPLEMENTATION-BACKED theorem to cite for end-to-end N1
byte-equality correctness is

```
Corona_N1_Extracted.corona_n1_byte_equality_extracted
```

The full per-axiom inventory lives in `AXIOM-INVENTORY.md`.
The Lean correspondence lives in `proofs/lean-easycrypt-bridge.md`.

## Compile

```bash
bash scripts/checks/ec-compile.sh
```

Requires `easycrypt` on PATH. Skips silently otherwise.
