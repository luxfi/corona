#!/usr/bin/env bash
# regen-kats.sh — deterministic regeneration + verification of every
# Corona KAT consumed by the C++ / GPU ports.
#
# Outputs (paths match what luxcpp/crypto/corona/test/kat/ expects):
#   <luxcpp>/crypto/corona/test/kat/reshare_kat.json
#   <luxcpp>/crypto/corona/dkg2/test/kat/dkg2_kat.json
#   <luxcpp>/crypto/corona/test/kat/activation_kat.json
#   <luxcpp>/crypto/corona/test/kat/corona_oracle_v2/{prng_blake2_xof,
#       discrete_gaussian, montgomery_ntt, structs_matrix_wire,
#       transcript_hash, shamir_share, sign_verify_e2e}.json
#
# In-tree NIST SP 800-185 KAT verification (no file output):
#   go test -count=1 -run "TestKMAC256NISTVector|TestTupleHash256NISTVector" ./hash
#
# At the end, writes a sha256 manifest of every regenerated file so a
# subsequent run with --verify can confirm byte-equality.

set -euo pipefail

CORONA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LUXCPP_DIR="${LUXCPP_DIR:-${HOME}/work/luxcpp}"
KAT_BASE="${LUXCPP_DIR}/crypto/corona"

RESHARE_OUT="${KAT_BASE}/test/kat/reshare_kat.json"
DKG2_OUT="${KAT_BASE}/dkg2/test/kat/dkg2_kat.json"
ACTIVATION_OUT="${KAT_BASE}/test/kat/activation_kat.json"
CORONA_V2_DIR="${KAT_BASE}/test/kat/corona_oracle_v2"

MANIFEST="${CORONA_DIR}/scripts/regen-kats.manifest.sha256"

VERIFY=0
if [[ "${1:-}" == "--verify" ]]; then
  VERIFY=1
fi

cd "${CORONA_DIR}"

# Corona oracles are indifferent to LUXCPP location through env vars and
# positional args. Run each, write to the canonical luxcpp path.
mkdir -p "$(dirname "${RESHARE_OUT}")" "$(dirname "${DKG2_OUT}")" "${CORONA_V2_DIR}"

echo "[1/5] reshare_oracle → ${RESHARE_OUT}"
PULSAR_RESHARE_KAT_PATH="${RESHARE_OUT}" go run ./cmd/reshare_oracle >/dev/null

# reshare_oracle hard-codes the path; if the env override isn't honored
# (older builds) fall back to copying the file the binary did write.
if [[ ! -f "${RESHARE_OUT}" ]]; then
  echo "ERROR: reshare_oracle did not produce ${RESHARE_OUT}"
  exit 1
fi

echo "[2/5] dkg2_oracle  → ${DKG2_OUT}"
PULSAR_DKG2_KAT_PATH="${DKG2_OUT}" go run ./cmd/dkg2_oracle >/dev/null

echo "[3/5] activation_oracle → ${ACTIVATION_OUT}"
PULSAR_ACTIVATION_KAT_PATH="${ACTIVATION_OUT}" go run ./cmd/activation_oracle >/dev/null

echo "[4/5] corona_oracle_v2 emit --out ${CORONA_V2_DIR}"
go run ./cmd/corona_oracle_v2 emit --out "${CORONA_V2_DIR}" >/dev/null

echo "[4b/5] corona_oracle_v2 byte-equality test"
go test -count=1 -run "TestEmitDeterministic|TestSignVerifyEntries|TestShamirRoundTrip" ./cmd/corona_oracle_v2 >/dev/null

echo "[5/5] hash NIST KAT verification"
go test -count=1 -run "TestKMAC256NISTVector|TestTupleHash256NISTVector" ./hash >/dev/null

# Build sha256 manifest deterministically (sorted by file name).
TMP_MANIFEST="$(mktemp)"
trap 'rm -f "${TMP_MANIFEST}"' EXIT

manifest_files=(
  "${RESHARE_OUT}"
  "${DKG2_OUT}"
  "${ACTIVATION_OUT}"
)
for f in "${CORONA_V2_DIR}"/*.json; do
  manifest_files+=("$f")
done

# Stable order regardless of glob expansion order. Paths in the
# manifest are relative to KAT_BASE so the manifest is portable
# across hosts (different ${HOME}).
printf '%s\n' "${manifest_files[@]}" | sort | while read -r f; do
  if [[ ! -f "$f" ]]; then
    echo "ERROR: expected output missing: $f" >&2
    exit 1
  fi
  rel="${f#${KAT_BASE}/}"
  shasum -a 256 "$f" | awk -v p="${rel}" '{print $1"  "p}'
done > "${TMP_MANIFEST}"

if [[ "${VERIFY}" == "1" ]]; then
  if [[ ! -f "${MANIFEST}" ]]; then
    echo "ERROR: --verify requested but no prior manifest at ${MANIFEST}"
    exit 2
  fi
  if ! diff -u "${MANIFEST}" "${TMP_MANIFEST}"; then
    echo "FAIL: manifest mismatch — KAT regeneration is non-deterministic" >&2
    exit 3
  fi
  echo "OK: KAT regeneration is byte-equal across runs ($(wc -l < "${MANIFEST}") files)"
else
  cp "${TMP_MANIFEST}" "${MANIFEST}"
  echo "wrote manifest: ${MANIFEST}"
  cat "${MANIFEST}"
fi
