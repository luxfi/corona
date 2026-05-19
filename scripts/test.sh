#!/usr/bin/env bash
# Corona test gate — orchestrator (per-push, REAL tests).
#
# Runs the available Go test surface for the production library
# plus KAT cross-runtime byte-equality verification.
#
# Corona's test surface is structurally simpler than Pulsar's:
# - No EasyCrypt theories to compile (Corona has none).
# - No Lean ↔ EC bridge to verify (Corona has none).
# - No Jasmin sources to type-check (Corona has none).
# - No jasmin-ct to run (Corona has no Jasmin path).
#
# See PROOF-CLAIMS.md §3 for the honest framing of why this gate is
# lighter than Pulsar's.
#
# The checks, in order:
#
#   1. Go unit + integration tests (with race detector)
#   2. KAT cross-runtime byte-equality (Go ↔ C++ luxcpp port)
#      if LUXCPP_DIR points at a populated checkout; SKIP otherwise.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

export GOWORK=off

echo "==> Step 1: go test (with -race)"
go test -count=1 -race ./...

echo
echo "==> Step 2: KAT cross-runtime byte-equality"
LUXCPP_DIR="${LUXCPP_DIR:-${HOME}/work/luxcpp}"
if [[ -d "${LUXCPP_DIR}/crypto/corona" ]] || [[ -d "${LUXCPP_DIR}/crypto/pulsar" ]]; then
    if [[ -x "$REPO_ROOT/scripts/regen-kats.sh" ]]; then
        bash "$REPO_ROOT/scripts/regen-kats.sh" --verify
    else
        echo "    [skip] scripts/regen-kats.sh not present or not executable"
    fi
else
    echo "    [skip] LUXCPP_DIR not populated; cross-runtime KAT check skipped"
    echo "    [info] set LUXCPP_DIR=/path/to/luxcpp and re-run to exercise the gate"
fi

echo
echo "==> done — test gate green"
