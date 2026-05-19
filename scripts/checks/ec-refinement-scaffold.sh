#!/usr/bin/env bash
# scripts/checks/ec-refinement-scaffold.sh -- Refinement-scaffold guard.
#
# The two refinement files (Combine_Refinement, Sign_Refinement) carry
# the byte-walk + memory-separation + layout-frame axioms today. CI
# surfaces declare-axiom shapes in them as warnings (they should be
# zero -- top-level `axiom` is fine; `declare axiom` is for the
# section-local module-contract axioms which live only in Corona_N1.ec).
#
# Separately: the same files MUST NOT contain top-level `declare axiom`
# statements -- this script flags any other declare axiom shape as a
# hard fail to prevent silent obligation drift.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EC_ROOT="$REPO_ROOT/proofs/easycrypt"

REFINE_FILES=(
    "$EC_ROOT/Corona_N1_Combine_Refinement.ec"
    "$EC_ROOT/Corona_N1_Sign_Refinement.ec"
)

echo "==> Refinement-scaffold status"

# Section-local declare-axioms live in Corona_N1.ec.
if grep -RE "^[[:space:]]*declare axiom[[:space:]]+combine_body_axiom" \
   "$EC_ROOT" >/dev/null 2>&1 ; then
    echo "    [warn] combine_body_axiom remains a section-local"
    echo "           refinement-boundary axiom (closed by Wrapper)"
fi
if grep -RE "^[[:space:]]*declare axiom[[:space:]]+S_functional_spec" \
   "$EC_ROOT" >/dev/null 2>&1 ; then
    echo "    [warn] S_functional_spec remains a section-local"
    echo "           refinement-boundary axiom (closed by Wrapper)"
fi

# The refinement files themselves should have zero declare axioms.
REFINE_DECLARE_AXIOMS=$(grep -RE "^[[:space:]]*declare axiom" \
    "${REFINE_FILES[@]}" 2>/dev/null || true)
if [[ -n "$REFINE_DECLARE_AXIOMS" ]]; then
    echo "    [FAIL] refinement scaffolds contain declare axioms:"
    echo "$REFINE_DECLARE_AXIOMS" | sed 's/^/      /'
    exit 2
fi
echo "    [ok]   no declare axiom in refinement scaffolds"
exit 0
