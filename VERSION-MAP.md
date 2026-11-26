# VERSION-MAP

One row per mapping across the four version axes of the S-01 suite:

| Axis | Meaning |
| --- | --- |
| Vector-set version | The published WIMSE HTTP signature test vector set (`set_version` in its `vectors.json`) |
| Draft version | The draft-ietf-wimse-http-signature version that vector set is mapped to (`draft_version`) |
| Suite version | The S-01 suite version: this repository's release (`pyproject.toml` `version`, `CITATION.cff` `version`) |
| Baseline-report fingerprint | SHA-256 of the recorded baseline file and of the canonical reports generated from it, for that row; "none recorded" when no baseline report exists |

The verifier itself implements draft-ietf-wimse-http-signature-09 in every
row registered so far; the -08/-09 skew is handled in [SKEW.md](SKEW.md),
not by this map.

## Rule: append-only

**This file is append-only from W7 (first registration, 2026-11-26) on.**

- Never edit, reorder or delete a registered row, in any future wave,
  even to fix it.
- A correction or a new mapping is a **new row** at the end of the table,
  with the next row id; a correcting row names the row it supersedes in
  its Notes cell (`supersedes M-n`). The superseded row stays as it was.
- Registering a row records a mapping; it changes no judgment, vector,
  baseline or expected value.
- `tests/test_w7_readme.py` fails if the rows registered at W7 (M-1,
  M-2) change by a single byte.

## Register

| Row | Registered | Vector-set version | Draft version | Suite version | Baseline-report fingerprint | Evidence | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| M-1 | W7, 2026-11-26 | v3 | draft-ietf-wimse-http-signature-08 | v0.1 | none recorded | The suite design's W7 wave row (the v3 ↔ -08 ↔ suite v0.1 correspondence), as stated in the W7 brief | Registered as the design states it. Not checkable in this repository: no set v3 data is vendored here, and no baseline or canonical report was ever produced against v3 (baselines start at W4, against v4). The fixture's `source.previous_version_doi` is 10.5281/zenodo.24184599; this repository does not record which set version that DOI holds. |
| M-2 | W7, 2026-11-26 | v4 | draft-ietf-wimse-http-signature-08 | v0.1 (0.1.0) | `baselines/s01-v4.json` SHA-256 `b98c35e40085744c48519ea4dac59b94958872730b1f8b98e20864f624ac696f`; canonical reports (from that baseline, commit 7a30ef0) `reports/s01-v4-canonical.json` SHA-256 `55974b063dae964b12e3dc84158b4b1ef6594198988a9a5372192f416faa1529`, `reports/s01-v4-canonical.md` SHA-256 `deaca78b1cf04f872337f0de3255be4406dd53dd7585df533b2191924fa600fa` | `tests/fixtures/vectors.json` header (`set_version` v4, `draft_version` -08; MD5 `b08b4063023d6194d90d273ce343e1af`, SHA-256 `b64b753dc89c93f0ae809ed9bd575d6718ac00e5169a07302dedf28407329b07`; archive DOI 10.5281/zenodo.24203971); `pyproject.toml` version 0.1.0; both canonical reports regenerate byte-identical at W7 (README "CLI: reports"; `scripts/selftest.sh` step 3) | v4 = 29 vectors, adding N-09b to the 22 earlier negatives (`vectors/v4/catalog.json`). N-09b contrast file `vectors/v4/n-09b.json` SHA-256 `aa99bdf52db1ec96418706886e3c83e680133250627587460630faa437495150`. |
