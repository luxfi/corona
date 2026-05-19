#!/usr/bin/env bash
# Corona high-assurance gate -- orchestrator (per-push, REAL checks).
#
# v0.7.0: Corona Tier A artifacts mirroring Pulsar's exactly:
#   13 EC files (Corona_N1..N4 + Layout + Refinement + Wrapper +
#                Extracted + lemmas/RLWE_Functional + lemmas/Corona_CT)
#   3 threshold + 1 rlwe Jasmin sources
#   1 Lean bridge md + 4 Lean files (Shamir + OutputInterchange +
#                                     Unforgeability + dkg2)
#   dudect harness on Verify + Combine
#
# The checks, in order:
#
#   1. jasmin.sh                  -- jasminc type-check + jasmin-ct
#                                    on the threshold layer (blocking).
#                                    Centralized rlwe/sign.jazz is advisory.
#   2. ec-admits.sh               -- EasyCrypt admit-budget (0/0).
#   3. ec-regressions.sh          -- Retired-axiom-shape regression guards.
#   4. ec-refinement-scaffold.sh  -- declare-axiom hygiene in the
#                                    Refinement files.
#   5. check-lean-bridge.sh       -- Lean<->EC Shamir bridge guard.
#   6. extraction.sh              -- Jasmin -> EC extraction sanity.
#   7. ec-compile.sh              -- All EC files compile clean.
#
# NOT in this gate (intentionally): dudect at smoke budget. A 10k-sample
# dudect run can't certify constant time; the budget isn't statistically
# meaningful. The REAL dudect gate is the submission-grade run from
# ct/dudect/run-submission.sh (10^9 samples per target on a pinned CPU).
#
# Per-check failure (exit 2) fails the orchestrator with the same code.
# Per-check skips (exit 0 with a [skip] message) do not fail the gate.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

CHECKS=(
    "scripts/checks/jasmin.sh"
    "scripts/checks/ec-admits.sh"
    "scripts/checks/ec-regressions.sh"
    "scripts/checks/ec-refinement-scaffold.sh"
    "scripts/check-lean-bridge.sh"
    "scripts/checks/extraction.sh"
    "scripts/checks/ec-compile.sh"
)

echo "==> Corona high-assurance track (v0.7.0)"
echo "    jasmin/   $REPO_ROOT/jasmin"
echo "    easycrypt $REPO_ROOT/proofs/easycrypt"
echo "    dudect    $REPO_ROOT/ct/dudect"
echo

OVERALL=0
for check in "${CHECKS[@]}"; do
    rc=0
    bash "$REPO_ROOT/$check" || rc=$?
    if [[ $rc -ne 0 ]]; then
        OVERALL=$rc
        echo
        echo "==> $check exited rc=$rc -- aborting gate"
        break
    fi
    echo
done

if [[ $OVERALL -eq 0 ]]; then
    echo "==> done -- high-assurance gate green"
fi
exit $OVERALL
