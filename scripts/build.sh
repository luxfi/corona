#!/usr/bin/env bash
# Corona reproducible build.
#
# Builds the Go reference implementation. Exits non-zero on any
# failure. Designed to be the CI gate.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Build in module-only mode. A surrounding workspace (e.g. ~/work/lux/go.work)
# does not own this repo's deps and must be bypassed deliberately so reviewers
# get the same view CI gets.
export GOWORK=off

echo "==> Go reference build"
go build ./...

# LaTeX paper-section build is optional — the canonical at this submission
# revision is SPEC.md (Markdown) + LaTeX paper sections at
# papers/lp-073-pulsar/. Build them only if latexmk is available.
if [[ -d "$REPO_ROOT/papers/lp-073-pulsar" ]]; then
    if [[ -x /Library/TeX/texbin/latexmk ]] && ! command -v latexmk >/dev/null 2>&1; then
        export PATH="/Library/TeX/texbin:$PATH"
    fi
    if command -v latexmk >/dev/null 2>&1; then
        echo "==> LaTeX paper-section build"
        (
            cd papers/lp-073-pulsar
            for tex in lp-073-pulsar-pedersen-dkg.tex lp-073-pulsar-resharing.tex; do
                if [[ -f "$tex" ]]; then
                    latexmk -pdf -interaction=nonstopmode -file-line-error "$tex" || {
                        echo "    [warn] $tex failed to build (continuing — paper sections are non-blocking at this submission revision)"
                    }
                fi
            done
        )
    else
        echo "    [info] latexmk not found; skipping paper-section PDF build"
        echo "    [info] (paper PDFs are non-blocking; submission canonical spec is SPEC.md at this revision)"
    fi
fi

echo "==> done"
