#!/usr/bin/env bash
# One-command self-test (S-01 W4 acceptance (c)): from a fresh clone,
#
#   bash scripts/selftest.sh
#
# sets up a local venv (.venv, unless one exists), then runs, failing fast:
#   1. pytest, ruff check, ruff format --check
#   2. every section 4.2 command form, with its expected exit status
#   3. the canonical report generated twice per format; the two files'
#      SHA-256 fingerprints must be equal
#   4. the W5 selfcheck: python selfcheck/run_selfcheck.py (must exit 0)
# Outputs land in build/selftest/ (git-ignored). Set PYTHON to choose the
# interpreter used to create the venv (default python3).
set -euo pipefail
cd "$(dirname "$0")/.."

if [ ! -x .venv/bin/python ]; then
  "${PYTHON:-python3}" -m venv .venv
  echo "creating .venv (install log: .venv/install.log)"
  .venv/bin/python -m pip install -q -e ".[dev]" >.venv/install.log 2>&1 \
    || { cat .venv/install.log; exit 1; }
fi
export PATH="$PWD/.venv/bin:$PATH"
PY=.venv/bin/python
OUT=build/selftest
rm -rf "$OUT" && mkdir -p "$OUT"
SET=(--set tests/fixtures/vectors.json --contrast vectors/v4/n-09b.json
     --baseline baselines/s01-v4.json)

step() { printf '\n== %s\n' "$*"; }
expect_exit() {  # expect_exit CODE LOGFILE CMD...
  local want=$1 log=$2; shift 2
  set +e; "$@" >"$log" 2>&1; local got=$?; set -e
  if [ "$got" != "$want" ]; then
    echo "FAIL: '$*' exited $got, expected $want"; cat "$log"; exit 1
  fi
  echo "ok (exit $got): $* -> $(tail -n 2 "$log" | tr '\n' ' ')"
}

step "1. unit + suite tests, lint, format"
$PY -m pytest -q -p no:cacheprovider
ruff check --no-cache src tests
ruff format --no-cache --check src tests

step "2. section 4.2 command forms"
AAV=($PY -m agent_auth_verifier)
expect_exit 0 "$OUT/run-all.txt" "${AAV[@]}" run --all "${SET[@]}"
expect_exit 0 "$OUT/run-id.txt" "${AAV[@]}" run --id N-09b "${SET[@]}"
expect_exit 0 "$OUT/run-class.txt" "${AAV[@]}" run --class negative-behavior "${SET[@]}"
expect_exit 2 "$OUT/run-unknown.txt" "${AAV[@]}" run --id X-99 "${SET[@]}"
expect_exit 1 "$OUT/run-strict.txt" "${AAV[@]}" run --all --set tests/fixtures/vectors.json
expect_exit 0 "$OUT/report-json.txt" "${AAV[@]}" report --format json "${SET[@]}" \
  --out "$OUT/report.json"
expect_exit 0 "$OUT/report-md.txt" "${AAV[@]}" report --format md "${SET[@]}" \
  --out "$OUT/report.md"

step "3. canonical report, generated twice per format"
for fmt in json md; do
  for i in 1 2; do
    PYTHONHASHSEED=$i "${AAV[@]}" report --format "$fmt" --canonical "${SET[@]}" \
      --out "$OUT/canonical-$i.$fmt"
  done
  a=$(sha256sum "$OUT/canonical-1.$fmt" | cut -d' ' -f1)
  b=$(sha256sum "$OUT/canonical-2.$fmt" | cut -d' ' -f1)
  echo "canonical.$fmt run 1 sha256 $a"
  echo "canonical.$fmt run 2 sha256 $b"
  if [ "$a" != "$b" ]; then echo "FAIL: canonical $fmt reports differ"; exit 1; fi
done

step "4. W5 selfcheck"
$PY selfcheck/run_selfcheck.py

step "SELFTEST PASS"
