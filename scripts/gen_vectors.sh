#!/usr/bin/env bash
# Corona KAT regeneration.
#
# Wraps scripts/regen-kats.sh — the canonical deterministic KAT
# regeneration entry point for Corona. The shape is "regenerate +
# verify byte-equal manifest"; CI uses --verify to enforce drift = bug.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [[ ! -x "$REPO_ROOT/scripts/regen-kats.sh" ]]; then
    echo "gen_vectors: scripts/regen-kats.sh missing or not executable" >&2
    exit 2
fi

# Pass through any user-supplied flags (e.g. --verify); default to
# regeneration (write fresh manifest).
bash "$REPO_ROOT/scripts/regen-kats.sh" "$@"
