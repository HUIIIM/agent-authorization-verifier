# W7 acceptance record (README, citations, CI gate)

Wave S-01 W7, 2026-11-26. The four acceptance items below are the W7
row's items as the W7 brief states them (the design document itself is
not in this repository). Each is closed individually with an evidence
pointer, or marked open with the reason.

| # | Item | Status | Evidence |
| --- | --- | --- | --- |
| 1 | README, tested: sources, citations, private-key warning, how-to-run; every printed command run literally in a clean environment; W4 contract wording kept | **CLOSED** | `README.md` sections "Private-key warning", "How to run", "Sources", "Citations"; `scripts/check_readme.py` ran all 22 command blocks in a fresh clone, 22/22 as stated (`w7-rehearsal/selftest-clean-clone-66868c8.log`, step 6); W4 `--class` domain, `run` exit-status and `report` wording guarded by `tests/test_w7_readme.py::test_readme_keeps_w4_contract_wording`; a false README claim fails the check (`w7-rehearsal/fault-4.log`) |
| 2 | CI merge gate: `run --all` plus the regen self-check, failing self-check blocks merge | **CLOSED in repo; one owner step open** | `.github/workflows/merge-gate.yml` runs `scripts/ci_gate.sh`; local rehearsal of the same script passes (log step 5); the gate fails on a diverging reading (exit 1, `fault-1.log`), a failing self-check (exit 1, `fault-2.log`) and a blocked self-check (exit 2, `fault-3.log`). Open: marking the check *required* is a branch-protection setting only the repository owner can make (see the PR's required-checks list) |
| 3 | VERSION-MAP.md first registration, append-only | **CLOSED** | `VERSION-MAP.md` rows M-1 (v3 / -08 / suite v0.1, as the design states; no v3 data or baseline in this repo, said in the row) and M-2 (v4 / -08 / 0.1.0, with SHA-256 of the baseline and both canonical reports, re-derived at W7); append-only rule stated in the file and hash-guarded by `tests/test_w7_readme.py::test_version_map_w7_rows_unchanged` |
| 4 | Chairs-form dependency register, item by item, true status | **OPEN (intake gap)** | `docs/chairs-form-register.md` holds the register and its status rules, but **no item is registered**: the item list lives in the design, which is not in this repository and was not enumerated in the brief, and no tracked file records any chairs-side form or reply. No item is recorded as answered. Awaiting the list; per the brief this does not block the wave |

## Clean-clone run: one command

```
git clone <repo> && cd <clone> && bash scripts/selftest.sh
```

Run at commit 66868c8 in a fresh `git clone --no-local`, with no virtualenv
on PATH (`PATH=/usr/local/bin:/usr/bin:/bin`), Python 3.13.18: exit 0,
`== SELFTEST PASS`, 24 s. Steps: (1) 142 tests passed, ruff check and
format clean; (2) every section 4.2 command form with its expected exit;
(3) canonical reports twice per format, SHA-256 equal (json `55974b06…`,
md `deaca78b…`, both equal to the committed reports); (4) W5 self-check
PASS; (5) CI gate rehearsal, `MERGE GATE PASS`; (6) README check, 22/22.
Full output: `w7-rehearsal/selftest-clean-clone-66868c8.log`.

## Boundaries kept

No file under `src/`, `tests/fixtures/`, `vectors/`, `baselines/` or
`selfcheck/` changed in W7. The gate adds a check and changes no
judgment; VERSION-MAP only registers.
