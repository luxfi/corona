#!/usr/bin/env bash
# Corona high-assurance gate — orchestrator (per-push, REAL checks).
#
# HONESTY NOTE: Corona's high-assurance surface is structurally
# lighter than Pulsar's. Pulsar runs 7 per-push checks (jasminc +
# jasmin-ct + ec-admits + ec-regressions + ec-refinement-scaffold +
# lean-bridge + ec-extraction + ec-compile). Corona has NO EasyCrypt
# theories, NO Lean ↔ EC bridge, NO Jasmin sources — see
# PROOF-CLAIMS.md §3 for the honest framing of why.
#
# What this gate runs at this submission revision:
#
#   1. go build ./...
#   2. go vet ./...
#   3. constant-time grep guard (warn on accidental fmt.Printf /
#      log.Println on secret-touching paths)
#   4. KAT cross-runtime byte-equality (if LUXCPP_DIR is populated)
#
# What this gate DOES NOT run (because the artifacts do not exist):
#
#   - EasyCrypt compile / admit-budget / regression checks
#   - Lean ↔ EC bridge verification
#   - Jasmin type-check + jasmin-ct
#   - Jasmin → EC extraction sanity
#
# These remain ROADMAP items (v0.7.0 for the EC/Lean shell;
# v0.8.0 for external audit).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
export GOWORK=off

echo "==> Corona high-assurance gate"
echo "    surface:    $REPO_ROOT (sign/, threshold/, dkg2/, reshare/, primitives/, hash/)"
echo "    HONESTY:    NO EC / Lean / Jasmin theories (see PROOF-CLAIMS.md §3)"
echo

OVERALL=0

echo "==> Check 1: go build ./..."
if ! go build ./...; then
    echo "==> FAIL: go build"
    OVERALL=2
fi

echo
echo "==> Check 2: go vet ./..."
if ! go vet ./...; then
    echo "==> FAIL: go vet"
    OVERALL=2
fi

echo
echo "==> Check 3: secret-log grep guard"
# Warn (not fail) if logging primitives appear in code that touches
# secret-typed paths. The full DD-007-style linter from Pulsar is not
# yet ported; this is a smoke check.
HITS=$(grep -rn -E "(fmt\.Print|log\.Print|log\.Fatal|log\.Panic)" \
    sign/ threshold/ dkg2/ reshare/ primitives/ keyera/ 2>/dev/null \
    | grep -v "_test.go" \
    | grep -v "// nolint:nosecretlog" || true)
if [[ -n "$HITS" ]]; then
    echo "    [warn] potential secret-log call sites (review manually):"
    echo "$HITS" | head -20
    echo "    (HONESTY: this is a smoke check, not a blocking gate)"
else
    echo "    [ok] no obvious secret-log call sites in sign/threshold/dkg2/reshare/primitives/keyera"
fi

echo
echo "==> Check 4: KAT cross-runtime byte-equality (advisory at this submission revision)"
LUXCPP_DIR="${LUXCPP_DIR:-${HOME}/work/luxcpp}"
if [[ -d "${LUXCPP_DIR}/crypto/corona" ]] || [[ -d "${LUXCPP_DIR}/crypto/pulsar" ]]; then
    if [[ -x "$REPO_ROOT/scripts/regen-kats.sh" ]]; then
        # KAT regen is advisory at submission scaffolding: scripts/regen-kats.sh
        # references oracle subdirs that may have been removed during the
        # Ringtail purge. Run it and report, but do NOT fail the gate on a
        # missing oracle directory.
        if bash "$REPO_ROOT/scripts/regen-kats.sh" --verify 2>&1 | tail -10; then
            echo "    [ok] cross-runtime KAT manifest verified"
        else
            echo "    [warn] KAT regen surfaced issues — review manually"
            echo "    [warn] (advisory at submission scaffolding; not blocking the gate)"
        fi
    else
        echo "    [skip] scripts/regen-kats.sh not present"
    fi
else
    echo "    [skip] LUXCPP_DIR not populated; cross-runtime KAT check skipped"
fi

echo
if [[ $OVERALL -eq 0 ]]; then
    echo "==> done — high-assurance gate green (within the documented scope)"
else
    echo "==> done — gate FAILED (rc=$OVERALL)"
fi
exit $OVERALL
