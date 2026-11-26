# Source anchor: old-base-signatures.json

`old-base-signatures.json` in this directory is a **vendored snapshot**
(vendored 快照) of the anti-mixing fixture. The vector repository remains
the original of record. If the two ever differ, the source wins: re-vendor
it here, byte-identical, and re-run the selfcheck.

| Field | Value |
| --- | --- |
| Source repo | `HUIIIM/wimse-http-signature-test-vectors` |
| Source path | `selfcheck/anti-mixing/old-base-signatures.json` |
| Source file MD5 | `a9ff2f3a31c7e2cf64fe44328cab0646` |
| Vendored copy | `selfcheck/fixtures/anti-mixing/old-base-signatures.json` (byte-identical; MD5 verified before the commit) |
| Vendored on | 2026-11-26 |

Each selfcheck run recomputes this copy's MD5 and prints it in the report
next to the source MD5 above.
