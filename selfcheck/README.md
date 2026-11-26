# selfcheck/

The S-01 W5 self-check set. It sits **outside the judgment path** (design
§4.6): it may import `agent_auth_verifier`, but nothing under `src/` may
import or depend on anything here. The runner checks that boundary on
every run.

## Run

From the repository root (needs the dev extras: `pytest`, `ruff`):

```bash
python selfcheck/run_selfcheck.py
```

`src/` is put on the path automatically; no install is needed. Each run
writes a new report, `reports/selfcheck-<YYYY-MM-DD>-r<N>.md`. `N` counts
up per date, so earlier reports are never overwritten. Pass `--date` to
set the date stamp yourself.

Exit code: `0` everything passes; `2` nothing failed but at least one
check was blocked (its inputs are missing); `1` something failed, or a
suite reading differs from the recorded expectation.

## What it runs

Acceptance checks:

| Id | Check | How |
| --- | --- | --- |
| (a) | Derived public keys match the JWK set fully | Re-derives every test key from `materials.key_derivation` (Ed25519 seed = SHA-256 of the label; the svcC P-256 scalar = SHA-256 mod (n-1) + 1), then compares all members with `materials.keys[*].public_jwk` and `private_d`, the trusted issuer anchor, and every WIT `cnf.jwk` |
| (b) | Positive examples + N-15 regeneration byte-identical | For P-01..P-06 and N-15, rebuilds each signature base, compares it with `signature_base_provided`, re-signs with the derived key (Ed25519; ES256 with RFC 6979 deterministic k), and compares the bytes with the literal signature |
| (b+) | Supplement: the regen negatives are reproducible | Builds each of the 17 negative-message vectors twice, from independent loads, and compares the bytes |
| (c) | Old-base signatures FAIL on the corrected base and PASS on the old base | Verifies each fixture in `fixtures/anti-mixing/` against both bases. Expects exactly 4 fixtures. Reports BLOCKED when none are present |

The five-item self-check list (as in the root `selfcheck.md`): `python -m
pytest -q`; `ruff check src tests`; `ruff format --check src tests`; an
`ast.parse` sweep over every tracked `.py` file; the CLI `run-vectors`
against `tests/fixtures/vectors.json`.

The suite readings are compared with the values the earlier waves
recorded: 22 matched; the N-09 divergence is attribution-only; N-09b is a
MATCH. Any difference is flagged **DIVERGENT** in the report. Recorded
values are never overwritten.

## Anti-mixing fixture format (provisional)

`fixtures/anti-mixing/<id>.json`, one file per old-base signature:

```json
{
  "id": "AM-1",
  "kid": "vec-a-key",
  "old_base": "<signature base as built before the correction, LF, no trailing newline>",
  "corrected_base": "<signature base the current code builds>",
  "signature": "<standard base64 of the raw signature bytes>"
}
```

`kid` names a key in `tests/fixtures/vectors.json` `materials.keys`. This
format is a placeholder. When the W2b fixtures arrive, adapt `check_c` in
`run_selfcheck.py` to their real format if it differs.
