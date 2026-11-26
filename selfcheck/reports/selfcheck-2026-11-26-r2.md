# Self-check report 2026-11-26 r2

Date: 2026-11-26. Revision r2 of this date. Produced by `python selfcheck/run_selfcheck.py`; every reading below was taken live by that run.

Code under test: commit `f929f9d53c678d7e7249e6da5f1fda4827c2e4ea`. Vector set: `tests/fixtures/vectors.json` (MD5 `b08b4063023d6194d90d273ce343e1af`).

Toolchain: Python 3.13.18, cryptography 50.0.1, pytest 9.1.1, ruff 0.16.9.

## Acceptance checks (a)-(c)

| Check | Command | Status | Result |
| --- | --- | --- | --- |
| (a) Derived public keys match the JWK set | `derive per materials.key_derivation` | **PASS** | 9/9 JWKs equal |
| (b) Positive examples + N-15 regeneration byte-identical | `rebuild base, re-sign (Ed25519; ES256 RFC 6979), compare bytes` | **PASS** | 8/8 signatures byte-identical (bases identical where provided) |
| (b+) Regen negatives reproducible (supplement) | `construct each negative-message vector twice` | **PASS** | 17/17 negative-message vectors byte-identical across two constructions |
| (c) Old-base signatures: FAIL on corrected base, PASS on old base | `verify each entry of selfcheck/fixtures/anti-mixing/old-base-signatures.json against old_base and corrected_base` | **PASS** | 4/4 entries PASS on old base and FAIL on corrected base; vendored MD5 identical to source; fixture corrected_base_verdict null (pending U4) for 4/4, so the corrected-base leg is judged against the W5 requirement only |

### (a) Derived public keys match the JWK set

- issuer (Ed25519, kid issuer-key): all members equal (crv, kty, x, private_d)
- svcA (Ed25519, kid vec-a-key): all members equal (crv, kty, x, private_d)
- svcB (Ed25519, kid vec-b-key): all members equal (crv, kty, x, private_d)
- svcC (ES256, kid vec-c-key): all members equal (crv, kty, x, y, private_d)
- other (Ed25519, kid other-key): all members equal (crv, kty, x, private_d)
- trusted_config.issuer_anchor_jwk (kid issuer-key): identical to the derived key's JWK
- wits[WIT-A].claims.cnf.jwk (kid vec-a-key): identical to the derived key's JWK
- wits[WIT-B].claims.cnf.jwk (kid vec-b-key): identical to the derived key's JWK
- wits[WIT-C].claims.cnf.jwk (kid vec-c-key): identical to the derived key's JWK

### (b) Positive examples + N-15 regeneration byte-identical

- P-01 sig1 (Ed25519, vec-a-key): base vs provided identical; regenerated signature byte-identical (64 bytes, sha256 fec8230163575510); literal verifies over rebuilt base: True
- P-02 sig1 (Ed25519, vec-b-key): base vs provided identical; regenerated signature byte-identical (64 bytes, sha256 ab8425670672b2f6); literal verifies over rebuilt base: True
- P-03 sig1 (ES256, vec-c-key): base vs provided identical; regenerated signature byte-identical (64 bytes, sha256 d6f51611f8d1b5ac); literal verifies over rebuilt base: True
- P-04 sig1 (Ed25519, vec-a-key): base vs provided identical; regenerated signature byte-identical (64 bytes, sha256 66131d494cb5ddb7); literal verifies over rebuilt base: True
- P-05 sig1 (Ed25519, vec-a-key): base vs provided identical; regenerated signature byte-identical (64 bytes, sha256 f76c4d8353e818fe); literal verifies over rebuilt base: True
- P-06 sig1 (Ed25519, other-key): base vs provided identical; regenerated signature byte-identical (64 bytes, sha256 e4f1584f206a9fb9); literal verifies over rebuilt base: True
- P-06 sig2 (Ed25519, vec-a-key): base vs provided identical; regenerated signature byte-identical (64 bytes, sha256 2e63aaa7fc33f3c7); literal verifies over rebuilt base: True
- N-15 sig1 (ES256, vec-c-key): base vs provided identical; regenerated signature byte-identical (64 bytes, sha256 bae31bf65e30e15d); literal verifies over rebuilt base: True

### (b+) Regen negatives reproducible (supplement)

- N-01 (literal): byte-identical
- N-02 (regen): byte-identical
- N-03 (literal): byte-identical
- N-04 (literal): byte-identical
- N-05 (literal): byte-identical
- N-06 (regen): byte-identical
- N-07 (regen): byte-identical
- N-08 (regen): byte-identical
- N-09 (literal): byte-identical
- N-09b (literal): byte-identical
- N-10 (regen): byte-identical
- N-11 (regen): byte-identical
- N-12 (regen): byte-identical
- N-13 (regen): byte-identical
- N-14 (none): byte-identical
- N-15 (literal): byte-identical
- N-21 (regen): byte-identical

### (c) Old-base signatures: FAIL on corrected base, PASS on old base

- Vendored copy MD5 `a9ff2f3a31c7e2cf64fe44328cab0646` vs source MD5 `a9ff2f3a31c7e2cf64fe44328cab0646` (HUIIIM/wimse-http-signature-test-vectors:selfcheck/anti-mixing/old-base-signatures.json): **identical**
- P-01 sig1 (Ed25519, signer svcA): old base PASS (fixture expects PASS); corrected base FAIL (fixture expects null, pending U4); corrected_base == suite signature_base_provided: True -> as required
- P-02 sig1 (Ed25519, signer svcB): old base PASS (fixture expects PASS); corrected base FAIL (fixture expects null, pending U4); corrected_base == suite signature_base_provided: True -> as required
- P-06 sig2 (Ed25519, signer svcA): old base PASS (fixture expects PASS); corrected base FAIL (fixture expects null, pending U4); corrected_base == suite signature_base_provided: True -> as required
- N-15 sig1 (ES256, signer svcC): old base PASS (fixture expects PASS); corrected base FAIL (fixture expects null, pending U4); corrected_base == suite signature_base_provided: True -> as required

## Five-item self-check list

| Check | Command | Status | Result |
| --- | --- | --- | --- |
| (1) Unit + suite tests | `python -m pytest -q` | **PASS** | 115 passed in 0.15s |
| (2) Lint | `ruff check src tests` | **PASS** | All checks passed! |
| (3) Format | `ruff format --check src tests` | **PASS** | 20 files already formatted |
| (4) Syntax sweep | `ast.parse over every tracked .py file` | **PASS** | 21 files, 21 parse |
| (5) Suite run (CLI) | `python -m agent_auth_verifier.cli run-vectors --set tests/fixtures/vectors.json` | **PASS** | 22 matched, 1 mismatched, 6 not judgeable by an artifact verifier (set v4, draft-ietf-wimse-http-signature-08); exit 1 |

## Suite readings vs recorded expectations

| Reading | Expected (recorded) | Live | Status |
| --- | --- | --- | --- |
| matched count | 22 | 22 | match |
| N-09 divergence classification | attribution-only | attribution-only | match |
| N-09b | MATCH | MATCH | match |

N-09 leg: `t=1795003600: expected REJECT/WINDOW/E_WINDOW_OUTSIDE, got REJECT/WIT/E_WIT_EXP -> MISMATCH`

N-09b legs: `t=1795000300: expected ACCEPT, got ACCEPT -> match`; `t=1795000301: expected REJECT/WINDOW/E_WINDOW_OUTSIDE, got REJECT/WINDOW/E_WINDOW_OUTSIDE -> match`

Divergences from recorded expectations: none.

## Boundary (design section 4.6)

| Check | Command | Status | Result |
| --- | --- | --- | --- |
| (4.6) Selfcheck outside the judgment path | `AST scan of src/**/*.py for imports of selfcheck` | **PASS** | no src/ module imports or references selfcheck |

## Overall

**PASS** -- 10 pass, 0 fail, 0 blocked; 0 divergent reading(s).
