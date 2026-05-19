#!/usr/bin/env bash
# Corona submission-grade dudect run.
#
# Runs the verify + combine harnesses with the full submission budget
# (10^9 samples per target). Designed for a quiet, CPU-pinned host
# (cpuset.cpus, governor=performance, no other workload).
#
# Mirrors ~/work/lux/pulsar/ct/dudect/run-submission.sh.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Submission-grade budget.
SAMPLES_PER_BATCH="${SAMPLES_PER_BATCH:-1000000}"
MAX_BATCHES="${MAX_BATCHES:-1000}"

# Pre-flight checks.
if ! command -v make >/dev/null 2>&1; then
    echo "==> make not found"
    exit 1
fi

if [[ ! -f "dudect/src/dudect.h" ]]; then
    echo "==> dudect.h missing -- running fetch.sh"
    bash ./fetch.sh
fi

echo "==> Building harnesses"
make clean
make

# Run verify.
echo
echo "==> dudect_verify ($SAMPLES_PER_BATCH samples * $MAX_BATCHES batches)"
DUDECT_SAMPLES="$SAMPLES_PER_BATCH" DUDECT_MAX_BATCHES="$MAX_BATCHES" \
    ./dudect_verify 2>&1 | tee verify.log
verify_rc="${PIPESTATUS[0]}"
echo "==> dudect_verify exit code: $verify_rc"

# Run combine.
echo
echo "==> dudect_combine ($SAMPLES_PER_BATCH samples * $MAX_BATCHES batches)"
DUDECT_SAMPLES="$SAMPLES_PER_BATCH" DUDECT_MAX_BATCHES="$MAX_BATCHES" \
    ./dudect_combine 2>&1 | tee combine.log
combine_rc="${PIPESTATUS[0]}"
echo "==> dudect_combine exit code: $combine_rc"

echo
echo "==> SUMMARY"
echo "    verify  exit: $verify_rc  (0 = no leakage evidence; 2 = leakage found)"
echo "    combine exit: $combine_rc  (0 = no leakage evidence; 2 = leakage found)"
echo
echo "    Submission verdict: PASS only when BOTH exit 0."

# Exit non-zero if either failed.
if [[ "$verify_rc" -ne 0 || "$combine_rc" -ne 0 ]]; then
    exit 2
fi
exit 0
