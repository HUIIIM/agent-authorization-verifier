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

## Faces

**Library** (Python >= 3.11, single runtime dependency: `cryptography`):

```python
from agent_auth_verifier import TrustedConfig, Verifier

verifier = Verifier(
    TrustedConfig(
        trusted_audiences=["https://svcb.example.com/gimme-ice-cream"],
        issuer_anchor_jwk={...},  # the WIT issuer trust anchor
    )
)
judgment = verifier.verify(raw_http_message, verify_time=1795000060)
judgment.verdict  # "ACCEPT" / "REJECT" / "CLIENT_REJECT"
judgment.failing_stage  # e.g. "COVERAGE" (None when accepted)
judgment.failing_code  # e.g. "E_COVERAGE_MISSING"
judgment.to_dict()  # machine-readable form of both layers
```

**CLI** (same core, no network access at runtime):

```console
# Judge one artifact
aav verify --message request.txt [--paired request.txt] \
    --config trusted-config.json --time 1795000060 [--json]

# Run a published test vector set end to end
aav run-vectors --set vectors.json [--json]

# Run a selection (design section 4.2): all, one vector, or one class
aav run --all --set tests/fixtures/vectors.json \
    --contrast vectors/v4/n-09b.json --baseline baselines/s01-v4.json
aav run --id N-09b --set ...        # one vector by id
aav run --class positive --set ...  # positive | negative-message | negative-behavior

# Reports (design section 4.3): one model, rendered as JSON or Markdown
aav report --format json|md --set ... [--all|--id ID|--class CLASS] \
    [--clock system|@UNIX|ISO8601] [--canonical] [--out PATH]
```

`run` exit status: with `--baseline`, 0 when every live reading equals the
recorded baseline (`baselines/s01-v4.json`) and 1 when any reading
diverges; without it, 0 only when every judgeable vector matches its
published expectation (so N-09's documented divergence exits 1, as
`run-vectors` does). An unknown id or class exits 2. `--contrast FILE`
also runs that contrast vector through the contrast engine (stepwise
table, CONTRAST_ANOMALY check) when its vector is selected.

`report` builds one plain-data model and renders it as either format, so
JSON and Markdown cannot drift. The only timestamp, `meta.generated_at`,
comes from the injected clock; the judgment path reads no clock at all
(time enters only as each evaluation's `verify_time`). `--canonical`
drops the `meta` envelope and normalizes key order and collection order,
so two runs over the same vector set give byte-identical files.

The trusted config file is JSON: `{"trusted_audiences": [...],
"issuer_anchor_jwk": {...}}`, with an optional `known_keys` list that only
refines failure classification (it lets the verifier distinguish an
algorithm-binding failure, section 3.1, from a plain invalid signature).

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

## Development

```console
pip install -e ".[dev]"
python -m pytest        # unit tests + the full suite v4 run
ruff check src tests
```

One command runs the whole self-test from a fresh clone (venv setup,
tests, lint, every `run`/`report` form, the dual canonical-report
fingerprint check, and the W5 `python selfcheck/run_selfcheck.py`):

```console
bash scripts/selftest.sh
```

## Licensing

Code: MIT (see [LICENSE](LICENSE)), copyright Jiahui Miao.
Test vector data in `tests/fixtures/vectors.json` is the published suite
v4 data, licensed CC-BY-4.0 by its publisher; it is included as a test
fixture and is not covered by this repository's MIT license. The excerpts
in `tests/fixtures/rfc9421/` are verbatim examples from RFC 9421
(Copyright (c) 2024 IETF Trust and the document authors; code components
under the Revised BSD License per the IETF Trust Legal Provisions), used
as test oracles and likewise not covered by the MIT license.
