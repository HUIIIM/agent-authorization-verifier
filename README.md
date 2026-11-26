# agent-authorization-verifier

A verification core for agent authorization over HTTP: it verifies and
interprets WIMSE workload-to-workload HTTP message signatures as specified
by **draft-ietf-wimse-http-signature-09** (the current version of the IETF
WIMSE draft), and reports *why* a message passes or fails, not just
whether it does.

Given an HTTP message (a request, or a response together with its paired
request), a trusted configuration (the WIT issuer anchor and the accepted
`wimse-aud` audiences), and a verification time, the verifier produces a
**two-layer judgment**:

- **Layer 1 -- the artifact verdict:** `ACCEPT`, `REJECT` (a request the
  server refuses, with the draft section 3.6 error surface), or
  `CLIENT_REJECT` (a response the client refuses).
- **Layer 2 -- the failure classification:** the first failing stage and
  its code, the full per-stage record, and any later stages that also
  fail (cascades). The twelve stages, in evaluation order, are the test
  vector suite's codes verbatim:

  `CONTEXT, PARSE, WIT, SELECT, PARAMS, COVERAGE, BASE, DIGEST, CRYPTO,
  AUD, BINDING, WINDOW`

The pipeline follows the draft's own processing order: the Workload
Identity Token (WIT) is validated before the message signature (section
3); the signature algorithm and key come only from the WIT `cnf.jwk`
binding (section 3.1); the WIMSE signature is selected by its `tag`
parameter, never by label (section 3); `wimse-aud` is compared against the
trusted configuration by RFC 3986 simple string comparison, with no
normalization (section 3.2); signed responses are bound to their request
by `wimse-req-nonce` (sections 3.4/3.5).

## Private-key warning

**The private keys in this repository are public test keys. Never use
them, or anything signed with them, outside testing.**

- `tests/fixtures/vectors.json` (the published suite set v4) carries the
  private half of every test key (`materials.keys[*].private_d`). Each
  key is derived deterministically from a public label
  (`SHA-256("s01-validation-vectors:<name>")`, see
  `materials.key_derivation`), so anyone can recompute it. Treat every
  key, WIT and signature in the fixtures as compromised by design.
- `selfcheck/fixtures/anti-mixing/old-base-signatures.json` holds
  signatures made with those same test keys.
- The verifier itself never needs a private key: it verifies with public
  keys only (the WIT issuer anchor, and the `cnf.jwk` the WIT binds).
  Private keys are read only to re-sign the suite's regenerated vectors
  (the vector runner, `src/agent_auth_verifier/vectors.py`, behind `aav
  run`, `aav run-vectors` and `aav report`; and the self-check), and only
  from the fixture.
- `examples/trusted-config.json` is the fixture's trusted configuration
  with **public** keys only; it contains no private key material.
- Never place a real private key in this repository, in a vector file or
  in a trusted config. A trusted config needs only public JWKs.

## How to run

All commands below are run from the root of a fresh clone of this
repository, on Linux with Python >= 3.11 and network access to the
package index. Each one is executed literally, in README order, in a
clean clone by `scripts/check_readme.py` (step 6 of the self-test), and
must produce the exit status and the output the text states.

### Set up

Create and activate a virtual environment, then install the package with
its development extras (`pytest`, `ruff`). Installing prints
`Successfully installed agent-authorization-verifier-0.1.0` among the
installed packages.

<!-- readme-check: exit=0 -->
```bash
python3 -m venv .venv
```

<!-- readme-check: exit=0 -->
```bash
. .venv/bin/activate
```

<!-- readme-check: exit=0 expect="Successfully installed" expect="agent-authorization-verifier-0.1.0" -->
```bash
python -m pip install -e ".[dev]"
```

### Library

Python >= 3.11, single runtime dependency: `cryptography`. This example
judges the N-10 request from `examples/` (an audience the trusted
configuration does not list) and prints `REJECT`, then
`AUD E_AUD_MISMATCH`, then the keys of the machine-readable judgment.

<!-- readme-check: exit=0 expect="REJECT" expect="AUD E_AUD_MISMATCH" expect="'failing_stage'" -->
```python
import json

from agent_auth_verifier import TrustedConfig, Verifier

with open("examples/trusted-config.json", encoding="utf-8") as f:
    config = json.load(f)
verifier = Verifier(
    TrustedConfig(
        trusted_audiences=config["trusted_audiences"],
        issuer_anchor_jwk=config["issuer_anchor_jwk"],  # the WIT issuer trust anchor
    )
)
with open("examples/n-10-request.http", encoding="utf-8", newline="") as f:
    raw_http_message = f.read()  # CRLF wire form; newline="" keeps it intact
judgment = verifier.verify(raw_http_message, verify_time=1795000060)
print(judgment.verdict)  # "ACCEPT" / "REJECT" / "CLIENT_REJECT"
print(judgment.failing_stage, judgment.failing_code)  # None None when accepted
print(sorted(judgment.to_dict()))  # machine-readable form of both layers
```

### CLI: judge one artifact

`aav verify` judges one HTTP message against a trusted config at a given
Unix time (`--paired REQUEST-FILE` adds the paired request when the
message is a response). It exits 0 when the verdict is `ACCEPT` and 1
otherwise. The `examples/` files are taken from suite set v4: P-01 (a
valid request) and N-10 (its `wimse-aud` has a trailing slash), with the
set's trusted configuration.

P-01 is accepted; every stage passes or is skipped:

<!-- readme-check: exit=0 expect="verdict: ACCEPT" expect="WINDOW    pass" -->
```bash
aav verify --message examples/p-01-request.http --config examples/trusted-config.json --time 1795000060
```

N-10 is rejected at the AUD stage:

<!-- readme-check: exit=1 expect="verdict: REJECT" expect="failing stage: AUD / E_AUD_MISMATCH" -->
```bash
aav verify --message examples/n-10-request.http --config examples/trusted-config.json --time 1795000060
```

`--json` prints the same judgment as JSON:

<!-- readme-check: exit=0 expect='"verdict": "ACCEPT"' expect='"failing_stage": null' -->
```bash
aav verify --message examples/p-01-request.http --config examples/trusted-config.json --time 1795000060 --json
```

The trusted config file is JSON: `{"trusted_audiences": [...],
"issuer_anchor_jwk": {...}}`, with an optional `known_keys` list that only
refines failure classification (it lets the verifier distinguish an
algorithm-binding failure, section 3.1, from a plain invalid signature).
`examples/trusted-config.json` is a complete instance.

### CLI: run the vector suite

`aav run-vectors` runs a published vector set end to end and compares
every judged vector with its published expectation. Against set v4 it
reports `22 matched, 1 mismatched, 6 not judgeable` and exits 1 (the
mismatch is N-09's documented attribution divergence):

<!-- readme-check: exit=1 expect="summary: 22 matched, 1 mismatched, 6 not judgeable" -->
```bash
aav run-vectors --set tests/fixtures/vectors.json
```

`aav run` runs a selection (design section 4.2): `--all`, one vector
(`--id ID`), or one class (`--class CLASS`, where CLASS is one of
`positive | negative-message | negative-behavior`). The full run with the
N-09b contrast vector and the recorded baseline exits 0 and reports
`baseline: no divergences`:

<!-- readme-check: exit=0 expect="summary: 22 matched, 1 mismatched, 6 not judgeable" expect="baseline: no divergences" -->
```bash
aav run --all --set tests/fixtures/vectors.json --contrast vectors/v4/n-09b.json --baseline baselines/s01-v4.json
```

One vector by id (N-09b, with its contrast table), exit 0:

<!-- readme-check: exit=0 expect="summary: 1 matched, 0 mismatched, 0 not judgeable" expect="selection id=N-09b" -->
```bash
aav run --id N-09b --set tests/fixtures/vectors.json --contrast vectors/v4/n-09b.json --baseline baselines/s01-v4.json
```

One class (the six positive vectors), exit 0:

<!-- readme-check: exit=0 expect="summary: 6 matched, 0 mismatched, 0 not judgeable" expect="selection class=positive" -->
```bash
aav run --class positive --set tests/fixtures/vectors.json --baseline baselines/s01-v4.json
```

Without `--baseline`, the same full run exits 1 (N-09):

<!-- readme-check: exit=1 expect="summary: 22 matched, 1 mismatched, 6 not judgeable" -->
```bash
aav run --all --set tests/fixtures/vectors.json
```

An unknown id exits 2:

<!-- readme-check: exit=2 expect="unknown vector id 'X-99'" -->
```bash
aav run --id X-99 --set tests/fixtures/vectors.json
```

`run` exit status: with `--baseline`, 0 when every live reading equals the
recorded baseline (`baselines/s01-v4.json`) and 1 when any reading
diverges; without it, 0 only when every judgeable vector matches its
published expectation (so N-09's documented divergence exits 1, as
`run-vectors` does). An unknown id or class exits 2. `--contrast FILE`
also runs that contrast vector through the contrast engine (stepwise
table, CONTRAST_ANOMALY check) when its vector is selected.

### CLI: reports

`aav report` (design section 4.3) takes the same selection options as
`run` (`--all`, the default; `--id`; `--class`) plus `--format json|md`,
`--clock system|@UNIX|ISO8601`, `--canonical` and `--out PATH` (the
directory of PATH must exist; without `--out` the report goes to
stdout). With a fixed clock, the Markdown report states that time:

<!-- readme-check: exit=0 expect="# Vector run report: set v4" expect="Generated at: 2026-11-26T00:00:00Z" -->
```bash
aav report --format md --set tests/fixtures/vectors.json --contrast vectors/v4/n-09b.json --baseline baselines/s01-v4.json --clock 2026-11-26T00:00:00Z
```

`report` builds one plain-data model and renders it as either format, so
JSON and Markdown cannot drift. The only timestamp, `meta.generated_at`,
comes from the injected clock; the judgment path reads no clock at all
(time enters only as each evaluation's `verify_time`). `--canonical`
drops the `meta` envelope and normalizes key order and collection order,
so two runs over the same vector set give byte-identical files.

The canonical JSON report is byte-identical to the recorded
`reports/s01-v4-canonical.json`; both have SHA-256
`55974b063dae964b12e3dc84158b4b1ef6594198988a9a5372192f416faa1529`
(GNU coreutils `sha256sum`):

<!-- readme-check: exit=0 expect="55974b063dae964b12e3dc84158b4b1ef6594198988a9a5372192f416faa1529  -" -->
```bash
aav report --format json --canonical --set tests/fixtures/vectors.json --contrast vectors/v4/n-09b.json --baseline baselines/s01-v4.json | sha256sum
```

<!-- readme-check: exit=0 expect="55974b063dae964b12e3dc84158b4b1ef6594198988a9a5372192f416faa1529  reports/s01-v4-canonical.json" -->
```bash
sha256sum reports/s01-v4-canonical.json
```

### Development checks

Unit tests plus the full suite v4 run, lint, and format check:

<!-- readme-check: exit=0 expect=" passed" -->
```bash
python -m pytest -q
```

<!-- readme-check: exit=0 expect="All checks passed!" -->
```bash
ruff check src tests
```

<!-- readme-check: exit=0 expect="files already formatted" -->
```bash
ruff format --check src tests
```

### Merge gate (CI)

`.github/workflows/merge-gate.yml` runs one job, **run-all + regen
self-check**, on every pull request, on pushes to the default branch, and
on manual dispatch. The job installs the package and runs
`scripts/ci_gate.sh`, which runs `aav run --all` against the recorded
baseline and then the regen self-check (`selfcheck/run_selfcheck.py`,
design section 4.6). A failing self-check blocks the merge just as a
failing run does; a blocked self-check (exit 2) blocks it too. The gate
changes no judgment. The same script runs locally and prints
`MERGE GATE PASS` when both steps pass (the self-check writes a new
dated report under `selfcheck/reports/`):

<!-- readme-check: exit=0 expect="== gate 1/2: run --all" expect="== gate 2/2: regen self-check" expect="== MERGE GATE PASS" -->
```bash
bash scripts/ci_gate.sh
```

### Full self-test (one command)

One command runs the whole self-test from a fresh clone: venv setup (it
reuses `.venv` if present), tests, lint, every `run`/`report` form, the
dual canonical-report fingerprint check, the W5 self-check, the CI gate
rehearsal (`scripts/ci_gate.sh`, the script the CI job runs), and this
README check. It ends with `== SELFTEST PASS`. (When it runs inside the
README check itself, step 6 reports itself as skipped instead of
recursing.)

<!-- readme-check: exit=0 expect="== 5. CI gate rehearsal" expect="== MERGE GATE PASS" expect="== SELFTEST PASS" -->
```bash
bash scripts/selftest.sh
```

The README check can list every command block it runs, with the exit
status and output each one must produce, without running them:

<!-- readme-check: exit=0 expect="blocks annotated" -->
```bash
python scripts/check_readme.py --list
```

## Interface with the test vector suite

The sole interface between this verifier and the WIMSE HTTP signature
test vector suite (HUIIIM/wimse-http-signature-test-vectors) is the
**vector set version**. This release is built and tested against:

- **Set v4**, mapped to draft-ietf-wimse-http-signature-08
  (data: CC-BY-4.0; archive DOI 10.5281/zenodo.24203971).

The verifier implements **-09**. The version skew is handled explicitly,
not papered over: see [SKEW.md](SKEW.md) for the -08/-09 diff analysis and
the per-vector applicability table. Headline: all 29 judged vectors of set
v4 remain applicable under -09; three of them (P-04, N-02, N-21) sit on
the one clarified clause (CONNECT `@authority`, draft issue #419), where
-09 confirms the construction the suite already uses. The suite runner in
this repository (`aav run-vectors`, and `tests/`) consumes the published
`vectors.json` directly, including its mutation/regeneration rules.

Current results against set v4 are recorded in
[selfcheck.md](selfcheck.md): 22 of 23 judgeable vectors match their
published expectation exactly; the remaining one (N-09) agrees on the
verdict and diverges only in primary-stage attribution for a reason the
suite's own anchor documents; the 6 behavior probes carry no artifact and
are reported as not judgeable by an artifact verifier.

## What v1 does not do

Deliberately out of scope for this first cut, by design:

- **No conformance mode.** Conformance (judging an implementation's
  behavior, including the suite's behavior probes) is a separate face
  that depends on the public benchmark; it is not built here. The
  pipeline is structured so a conformance face can be added without
  touching the verification core, and nothing in v1 claims conformance
  results.
- **No token issuance.** This is a verifier only; it does not mint WITs
  or any other tokens.
- **No revocation or status lookups.** No live queries of any kind; the
  library and CLI perform **no network access at runtime**.
- **No additional protocol profiles.** OSAP, AA, Poppy and similar
  profiles are not implemented and are not claimed; extension points are
  left clean for them.
- **Component coverage** is the profile's set: `@method`, `@path`,
  `@query`, `@authority`, `@status` (with `;req`), plus header fields.
  Other RFC 9421 derived components and component parameters (`;sf`,
  `;bs`, `;name`, `;key`, ...) are rejected as unsupported rather than
  silently mishandled.
  Signature base construction applies the RFC 9421 Section 2.5 error
  rules as hard BASE failures: a duplicated component identifier, any
  misuse of `;req` (never a fallback to the other message), and a
  non-ASCII base. `@authority` omits the default port of the resolved
  scheme (https 443, http 80); the scheme is the artifact's explicit one
  (absolute-form target) or else the profile default https.
- **Algorithms** are the ones the profile binds through `cnf.jwk.alg`:
  Ed25519 and ES256.

## Sources

What this repository is built from, and where each piece lives here:

| Source | Identifier | Used for | In this repository |
| --- | --- | --- | --- |
| WIMSE HTTP signature draft, implemented version | draft-ietf-wimse-http-signature-09, <https://datatracker.ietf.org/doc/draft-ietf-wimse-http-signature/> | the verification rules | `src/` |
| WIMSE HTTP signature draft, version the vectors map to | draft-ietf-wimse-http-signature-08 | the -08/-09 skew analysis | [SKEW.md](SKEW.md) |
| WIMSE workload credentials draft | draft-ietf-wimse-workload-creds-03, section 5.1.3 | the WIT pre-checks (W3 gate U3) | [docs/w3-wit-u3.md](docs/w3-wit-u3.md) |
| HTTP Message Signatures | RFC 9421 | signature base construction; verbatim examples as test oracles | `tests/fixtures/rfc9421/` (manifest: `manifest.json`) |
| URI generic syntax | RFC 3986, simple string comparison | `wimse-aud` comparison | `src/` |
| WIMSE HTTP signature test vector suite, set v4 | HUIIIM/wimse-http-signature-test-vectors; archive DOI 10.5281/zenodo.24203971 (previous version DOI 10.5281/zenodo.24184599); CC-BY-4.0 | the suite the verifier is judged against | `tests/fixtures/vectors.json` (byte-identical copy, MD5 `b08b4063023d6194d90d273ce343e1af`); `vectors/v4/` |
| Anti-mixing old-base signatures | HUIIIM/wimse-http-signature-test-vectors, `selfcheck/anti-mixing/old-base-signatures.json` (MD5 `a9ff2f3a31c7e2cf64fe44328cab0646`) | self-check (c) | `selfcheck/fixtures/anti-mixing/` ([SOURCE.md](selfcheck/fixtures/anti-mixing/SOURCE.md)) |

The vector set, draft and suite versions are registered, one row per
mapping, in [VERSION-MAP.md](VERSION-MAP.md). Form dependencies on the
WG chairs' side are registered in
[docs/chairs-form-register.md](docs/chairs-form-register.md).

## Citations

To cite this software, use [CITATION.cff](CITATION.cff) (GitHub shows it
as "Cite this repository"):

> Miao, Jiahui. *agent-authorization-verifier*, version 0.1.0 (2026).
> https://github.com/HUIIIM/agent-authorization-verifier

When you report results obtained with it, also cite what they were
obtained against:

- The test vector suite: *Test Vectors for the WIMSE S2S Protocol HTTP
  Signature Scheme*, set v4, DOI
  [10.5281/zenodo.24203971](https://doi.org/10.5281/zenodo.24203971),
  CC-BY-4.0. The CC-BY-4.0 license requires attribution when you reuse
  the vector data, including the copy in `tests/fixtures/vectors.json`.
- The draft: draft-ietf-wimse-http-signature-09 (implemented); the
  vector set maps to draft-ietf-wimse-http-signature-08.
- RFC 9421, *HTTP Message Signatures* (A. Backman, J. Richer, M. Sporny,
  2024).

## Licensing

Code: MIT (see [LICENSE](LICENSE)), copyright Jiahui Miao.
Test vector data in `tests/fixtures/vectors.json` is the published suite
v4 data, licensed CC-BY-4.0 by its publisher; it is included as a test
fixture and is not covered by this repository's MIT license. The excerpts
in `tests/fixtures/rfc9421/` are verbatim examples from RFC 9421
(Copyright (c) 2024 IETF Trust and the document authors; code components
under the Revised BSD License per the IETF Trust Legal Provisions), used
as test oracles and likewise not covered by the MIT license.
The files in `examples/` (`p-01-request.http`, `n-10-request.http`,
`trusted-config.json`) are taken from the same suite v4 data (vectors
P-01 and N-10, and the set's trusted configuration with its public keys)
and are likewise CC-BY-4.0, not MIT; `tests/test_w7_readme.py` checks
that they stay identical to what the fixture yields.
