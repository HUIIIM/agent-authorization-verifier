#!/usr/bin/env bash
# S-01 merge gate (W7; design section 4.6). This one script is what the CI
# workflow (.github/workflows/merge-gate.yml) runs, and what
# scripts/selftest.sh runs as its local CI rehearsal, so the two cannot
# drift. It only gates; it changes no judgment, vector, baseline or
# expected value. Either step failing blocks the merge:
#
#   1. aav run --all against set v4 with the N-09b contrast vector and the
#      recorded baseline: exit 0 only when every live reading equals
#      baselines/s01-v4.json
#   2. the regen self-check: python selfcheck/run_selfcheck.py, which must
#      exit 0 (exit 1 = a check failed, exit 2 = a check was blocked;
#      both block, as a failing run does)
#
# Needs the package and its dev extras installed (pip install -e ".[dev]").
# Set PY to choose the interpreter (default: python on PATH).
set -euo pipefail
cd "$(dirname "$0")/.."
PY=${PY:-python}

echo "== gate 1/2: run --all (baseline reconciliation)"
"$PY" -m agent_auth_verifier run --all --set tests/fixtures/vectors.json \
  --contrast vectors/v4/n-09b.json --baseline baselines/s01-v4.json

echo "== gate 2/2: regen self-check (selfcheck/run_selfcheck.py)"
"$PY" selfcheck/run_selfcheck.py

echo "== MERGE GATE PASS"
