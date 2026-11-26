# Vector run report: set v4

- Schema: `aav-report/1`
- Tool: agent-authorization-verifier 0.1.0 (draft-ietf-wimse-http-signature-09)
- Set: `vectors.json` (set v4, draft draft-ietf-wimse-http-signature-08); MD5 `b08b4063023d6194d90d273ce343e1af`; SHA-256 `b64b753dc89c93f0ae809ed9bd575d6718ac00e5169a07302dedf28407329b07`
- Selection: all

## Summary

| Total | Matched | Mismatched | Not judgeable | Contrast pass | Contrast fail |
| --- | --- | --- | --- | --- | --- |
| 29 | 22 | 1 | 6 | 1 | 0 |

| Reading | Vectors |
| --- | --- |
| MATCH | P-01, P-02, P-03, P-04, P-05, P-06, N-01, N-02, N-03, N-04, N-05, N-06, N-07, N-08, N-09b, N-10, N-11, N-12, N-13, N-14, N-15, N-21 |
| NOT_JUDGEABLE | N-16, N-17, N-18, N-19, N-20, N-22 |
| attribution-only | N-09 |

## Vectors

| Vector | Kind | Mode | t | Expected | Actual | Match | Reading |
| --- | --- | --- | --- | --- | --- | --- | --- |
| P-01 | positive | oracle | 1795000060 | ACCEPT | ACCEPT | yes | MATCH |
| P-02 | positive | oracle | 1795000060 | ACCEPT | ACCEPT | yes | MATCH |
| P-03 | positive | oracle | 1795000060 | ACCEPT | ACCEPT | yes | MATCH |
| P-04 | positive | oracle | 1795000060 | ACCEPT | ACCEPT | yes | MATCH |
| P-05 | positive | oracle | 1795000060 | ACCEPT | ACCEPT | yes | MATCH |
| P-06 | positive | oracle | 1795000060 | ACCEPT | ACCEPT | yes | MATCH |
| N-01 | negative-message | oracle | 1795000060 | REJECT COVERAGE/E_COVERAGE_MISSING | REJECT COVERAGE/E_COVERAGE_MISSING (cascades: CRYPTO) | yes | MATCH |
| N-02 | negative-message | oracle | 1795000060 | REJECT COVERAGE/E_COVERAGE_FORBIDDEN | REJECT COVERAGE/E_COVERAGE_FORBIDDEN (cascades: BASE) | yes | MATCH |
| N-03 | negative-message | oracle | 1795000060 | REJECT COVERAGE/E_DIGEST_MISSING | REJECT COVERAGE/E_DIGEST_MISSING (cascades: CRYPTO) | yes | MATCH |
| N-04 | negative-message | oracle | 1795000060 | REJECT DIGEST/E_DIGEST_MISMATCH | REJECT DIGEST/E_DIGEST_MISMATCH | yes | MATCH |
| N-05 | negative-message | oracle | 1795000060 | REJECT PARAMS/E_PARAM_MISSING | REJECT PARAMS/E_PARAM_MISSING (cascades: CRYPTO) | yes | MATCH |
| N-06 | negative-message | oracle | 1795000060 | REJECT PARAMS/E_PARAM_FORBIDDEN | REJECT PARAMS/E_PARAM_FORBIDDEN | yes | MATCH |
| N-07 | negative-message | oracle | 1795000060 | REJECT PARAMS/E_PARAM_FORBIDDEN | REJECT PARAMS/E_PARAM_FORBIDDEN | yes | MATCH |
| N-08 | negative-message | oracle | 1795000060 | REJECT SELECT/E_TAG_AMBIGUOUS | REJECT SELECT/E_TAG_AMBIGUOUS | yes | MATCH |
| N-09 | negative-message | oracle | 1795003600 | REJECT WINDOW/E_WINDOW_OUTSIDE | REJECT WIT/E_WIT_EXP (cascades: WINDOW) | no | attribution-only |
| N-09b | negative-message | contrast | 1795000300 | ACCEPT | ACCEPT | yes | MATCH |
| N-09b | negative-message | contrast | 1795000301 | REJECT WINDOW/E_WINDOW_OUTSIDE | REJECT WINDOW/E_WINDOW_OUTSIDE | yes | MATCH |
| N-10 | negative-message | oracle | 1795000060 | REJECT AUD/E_AUD_MISMATCH | REJECT AUD/E_AUD_MISMATCH | yes | MATCH |
| N-11 | negative-message | oracle | 1795000060 | REJECT PARAMS/E_PARAM_MISSING | REJECT PARAMS/E_PARAM_MISSING | yes | MATCH |
| N-12 | negative-message | oracle | 1795000060 | CLIENT_REJECT PARAMS/E_REQNONCE_MISSING | CLIENT_REJECT PARAMS/E_REQNONCE_MISSING | yes | MATCH |
| N-13 | negative-message | oracle | 1795000060 | CLIENT_REJECT BINDING/E_REQNONCE_MISMATCH | CLIENT_REJECT BINDING/E_REQNONCE_MISMATCH | yes | MATCH |
| N-14 | negative-message | oracle | 1795000060 | CLIENT_REJECT BINDING/E_RESPONSE_UNSIGNED | CLIENT_REJECT BINDING/E_RESPONSE_UNSIGNED | yes | MATCH |
| N-15 | negative-message | oracle | 1795000060 | REJECT CRYPTO/E_ALG_BINDING | REJECT CRYPTO/E_ALG_BINDING | yes | MATCH |
| N-16 | negative-behavior | probe | - | - | - | - | NOT_JUDGEABLE |
| N-17 | negative-behavior | probe | - | - | - | - | NOT_JUDGEABLE |
| N-18 | negative-behavior | probe | - | - | - | - | NOT_JUDGEABLE |
| N-19 | negative-behavior | probe | - | - | - | - | NOT_JUDGEABLE |
| N-20 | negative-behavior | probe | - | - | - | - | NOT_JUDGEABLE |
| N-21 | negative-message | oracle | 1795000060 | CLIENT_REJECT COVERAGE/E_COVERAGE_FORBIDDEN | CLIENT_REJECT COVERAGE/E_COVERAGE_FORBIDDEN (cascades: BASE) | yes | MATCH |
| N-22 | negative-behavior | probe | - | - | - | - | NOT_JUDGEABLE |

Notes:

- N-16: behavior probe, subject=sender: an artifact verifier cannot judge implementation behavior (expected NONCONFORMANT/E_ENTROPY if the probed behavior occurs)
- N-17: behavior probe, subject=server: an artifact verifier cannot judge implementation behavior (expected NONCONFORMANT/E_ERROR_SURFACE if the probed behavior occurs)
- N-18: behavior probe, subject=server: an artifact verifier cannot judge implementation behavior (expected NONCONFORMANT/E_UNSIGNED_SUCCESS if the probed behavior occurs)
- N-19: behavior probe, subject=sender: an artifact verifier cannot judge implementation behavior (expected NONCONFORMANT/E_ACCEPT_SIG_WEAK if the probed behavior occurs)
- N-20: behavior probe, subject=verifier: an artifact verifier cannot judge implementation behavior (expected NONCONFORMANT/E_PROCESS_ORDER if the probed behavior occurs)
- N-22: behavior probe, subject=verifier: an artifact verifier cannot judge implementation behavior (expected NONCONFORMANT/E_SELECTION_BY_LABEL if the probed behavior occurs)

## Contrast surface

### N-09b: pass

Source: `v4/n-09b.json` (MD5 `dd500564b55cd047580f86b2f107d73c`; catalog MD5 match: yes). Anomalies: none.

| Step | Label | Invariant | t=1795000300 | t=1795000301 |
| --- | --- | --- | --- | --- |
| 1 | WIT issuer signature | yes | pass | pass |
| 1b | WIT cnf binding | yes | pass | pass |
| 1c | WIT not expired | no | pass | pass |
| 2 | Message signature cryptography | yes | pass | pass |
| 3 | Coverage and required parameters | yes | pass | pass |
| 4 | wimse-aud match | yes | pass | pass |
| 5 | Signature validity window | no | pass | fail (E_WINDOW_OUTSIDE) |
| final | Final judgment | no | ACCEPT | REJECT (E_WINDOW_OUTSIDE) |

- t=1795000300: ACCEPT; match: yes
- t=1795000301: REJECT WINDOW/E_WINDOW_OUTSIDE; match: yes

## Reconciliation against the recorded baseline

Baseline: `baselines/s01-v4.json` (SHA-256 `b98c35e40085744c48519ea4dac59b94958872730b1f8b98e20864f624ac696f`).

| Item | Expected (recorded) | Live | Status |
| --- | --- | --- | --- |
| contrast.N-09b | `{"anomalies":0,"verdict":"pass"}` | `{"anomalies":0,"verdict":"pass"}` | match |
| set.md5 | b08b4063023d6194d90d273ce343e1af | b08b4063023d6194d90d273ce343e1af | match |
| summary.matched | 22 | 22 | match |
| summary.mismatched | 1 | 1 | match |
| summary.not_judgeable | 6 | 6 | match |
| vector.N-01 | MATCH | MATCH | match |
| vector.N-02 | MATCH | MATCH | match |
| vector.N-03 | MATCH | MATCH | match |
| vector.N-04 | MATCH | MATCH | match |
| vector.N-05 | MATCH | MATCH | match |
| vector.N-06 | MATCH | MATCH | match |
| vector.N-07 | MATCH | MATCH | match |
| vector.N-08 | MATCH | MATCH | match |
| vector.N-09 | attribution-only | attribution-only | match |
| vector.N-09b | MATCH | MATCH | match |
| vector.N-10 | MATCH | MATCH | match |
| vector.N-11 | MATCH | MATCH | match |
| vector.N-12 | MATCH | MATCH | match |
| vector.N-13 | MATCH | MATCH | match |
| vector.N-14 | MATCH | MATCH | match |
| vector.N-15 | MATCH | MATCH | match |
| vector.N-16 | NOT_JUDGEABLE | NOT_JUDGEABLE | match |
| vector.N-17 | NOT_JUDGEABLE | NOT_JUDGEABLE | match |
| vector.N-18 | NOT_JUDGEABLE | NOT_JUDGEABLE | match |
| vector.N-19 | NOT_JUDGEABLE | NOT_JUDGEABLE | match |
| vector.N-20 | NOT_JUDGEABLE | NOT_JUDGEABLE | match |
| vector.N-21 | MATCH | MATCH | match |
| vector.N-22 | NOT_JUDGEABLE | NOT_JUDGEABLE | match |
| vector.P-01 | MATCH | MATCH | match |
| vector.P-02 | MATCH | MATCH | match |
| vector.P-03 | MATCH | MATCH | match |
| vector.P-04 | MATCH | MATCH | match |
| vector.P-05 | MATCH | MATCH | match |
| vector.P-06 | MATCH | MATCH | match |

Divergences: none.
