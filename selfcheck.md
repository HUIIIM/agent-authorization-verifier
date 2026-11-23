# Self-check: agent-authorization-verifier v0.1.0 (first cut)

Date: 2026-11-23. Everything below was produced by running the code in
this directory; commands and outputs are reproducible as shown.

## Toolchain and checks

Environment used for this self-check: Python 3.12.3, cryptography 50.0.2,
pytest 9.2.0, ruff 0.17.6 (development venv outside the tree). The package
declares Python >= 3.11 and cryptography >= 42.

| Check | Command | Result |
|---|---|---|
| Unit + suite tests | `python -m pytest -q` | **42 passed, 0 failed** |
| Lint | `ruff check src tests` | **clean (no findings)** |
| Format | `ruff format --check src tests` | **16 files, all formatted** |
| Syntax sweep | `ast.parse` over every .py file | **16 files, all parse** |
| Suite run (CLI) | `aav run-vectors --set tests/fixtures/vectors.json` | 22 matched, 1 mismatched, 6 not judgeable; exit 1 (see N-09) |

Test breakdown (42): structured-fields parsing/serialization 11;
signature-base construction 11 (including byte-equality against all 8
published signature bases: P-01..P-06, N-09b, N-15); cryptography and WIT
validation 6 (including independent recomputation of the suite's
deterministic key derivations for all five test keys); the end-to-end
vector run 11; CLI surface 3.

## Fixture provenance

`tests/fixtures/vectors.json` is a byte-identical copy of the published
suite v4 data (set v4, draft-ietf-wimse-http-signature-08, CC-BY-4.0,
archive DOI 10.5281/zenodo.24203971). MD5 of both the fixture and the
source copy: `b08b4063023d6194d90d273ce343e1af`.

Vectors that carry no literal message were constructed from their base
vector plus the recorded mutation; where the fixture marks
`signature_source: regen`, the mutated message was re-signed with the
published test materials per the suite's regeneration rule A-04. All
regenerated members in set v4 are Ed25519, hence deterministic:
constructing N-02, N-06, N-08, N-12 and N-21 twice produces byte-identical
artifacts (verified).

## Per-vector outcomes (29 judged vectors)

Match criterion: layer-1 verdict equal, and for rejections the failing
stage and code equal. Cascades are reported but are not part of the
criterion (see the cascade note below).

| Vector | Expected | Actual | Result |
|---|---|---|---|
| P-01 | ACCEPT | ACCEPT | match |
| P-02 | ACCEPT | ACCEPT | match |
| P-03 | ACCEPT | ACCEPT | match |
| P-04 | ACCEPT | ACCEPT | match |
| P-05 | ACCEPT | ACCEPT | match |
| P-06 | ACCEPT | ACCEPT (selected sig2, by tag) | match |
| N-01 | REJECT COVERAGE/E_COVERAGE_MISSING | same | match |
| N-02 | REJECT COVERAGE/E_COVERAGE_FORBIDDEN | same | match |
| N-03 | REJECT COVERAGE/E_DIGEST_MISSING | same | match |
| N-04 | REJECT DIGEST/E_DIGEST_MISMATCH | same | match |
| N-05 | REJECT PARAMS/E_PARAM_MISSING | same | match |
| N-06 | REJECT PARAMS/E_PARAM_FORBIDDEN | same | match |
| N-07 | REJECT PARAMS/E_PARAM_FORBIDDEN | same | match |
| N-08 | REJECT SELECT/E_TAG_AMBIGUOUS | same | match |
| N-09 | REJECT WINDOW/E_WINDOW_OUTSIDE | REJECT WIT/E_WIT_EXPIRED, cascade [WINDOW] | **divergence (attribution only)** |
| N-09b | ACCEPT at T0+300; REJECT WINDOW/E_WINDOW_OUTSIDE at T0+301 | same, both legs | match |
| N-10 | REJECT AUD/E_AUD_MISMATCH | same | match |
| N-11 | REJECT PARAMS/E_PARAM_MISSING | same | match |
| N-12 | CLIENT_REJECT PARAMS/E_REQNONCE_MISSING | same | match |
| N-13 | CLIENT_REJECT BINDING/E_REQNONCE_MISMATCH | same | match |
| N-14 | CLIENT_REJECT BINDING/E_RESPONSE_UNSIGNED | same | match |
| N-15 | REJECT CRYPTO/E_ALG_BINDING | same | match |
| N-16 | probe, subject sender | not judgeable by an artifact verifier | scope boundary |
| N-17 | probe, subject server | not judgeable | scope boundary |
| N-18 | probe, subject server | not judgeable | scope boundary |
| N-19 | probe, subject sender | not judgeable | scope boundary |
| N-20 | probe, subject verifier | not judgeable | scope boundary |
| N-21 | CLIENT_REJECT COVERAGE/E_COVERAGE_FORBIDDEN | same | match |
| N-22 | probe, subject verifier | not judgeable (but see note) | scope boundary |

Note on N-22: the probe judges whether *an implementation under test*
selects by label. This verifier's own behavior on the probe's scenario is
directly evidenced by P-06: it selects sig2 (the tag match), never the
first label. That is implementation evidence, not a probe judgment.

## The N-09 divergence (named, not hidden)

N-09 verifies P-01's message at T0+3600 and expects attribution to
WINDOW. At that instant, WIT-A is also expired -- its exp is exactly
T0+3600, and a JWT MUST NOT be accepted at or after exp. This verifier
validates the WIT before the message signature, as the draft mandates in
both -08 and -09, so it attributes the failure to WIT/E_WIT_EXPIRED and
reports WINDOW as a cascade. The verdict (REJECT) agrees with the suite.

This is a confound the suite itself records in N-09's anchor: "at that
time WIT-A is also expired; attribution isolation is weak; the source
decision rule judges only the time window." Control evidence that the
WINDOW stage itself is correct: the same artifact at T0+1800 (WIT still
valid, signature window closed) is attributed to WINDOW/E_WINDOW_OUTSIDE,
and N-09b's boundary legs (T0+300 accept, T0+301 reject) both match.
Classification: suite-side attribution confound at a boundary instant --
not a code bug, and not draft skew (the WIT-first rule and the window
rule are identical in -08 and -09; section 3.6 in any case forbids
distinguishing which check failed in the error response). The strict
comparison in `aav run-vectors` therefore exits 1; the pytest suite
encodes this documented expectation explicitly.

## Cascade semantics note

The suite's `cascades` field and this verifier's differ in semantics.
The suite's values are consistent with "stages that would still fail
after a minimal repair of the primary defect"; this verifier reports
"stages that also fail on the artifact as presented". Divergences, all
outside the match criterion: N-01, N-03, N-05 (this verifier also reports
CRYPTO, because the literal signature no longer verifies over the mutated
base; the suite reports none), N-04 (the suite reports CRYPTO; here the
base is built from the unchanged header value, so the signature still
verifies and CRYPTO passes), N-09 (this verifier reports WINDOW as a
cascade; see above). The primary stage and code agree in every case
except N-09's, as tabled.

## Gaps and limits (honest list)

1. **Behavior probes are not judged** (6 of 29). They test implementation
   behavior (sender entropy, server error surface, processing order),
   which an artifact verifier cannot observe. The conformance face that
   would judge them is not built in v1 (per the brief, it waits for the
   public benchmark); nothing here claims conformance results.
2. **Cascade semantics** differ from the suite's, as analyzed above;
   cascades are informational in the runner's comparison.
3. **ES256 regeneration is not byte-reproducible**: the signing helper
   uses the cryptography library's ECDSA (randomized k), not RFC 6979
   deterministic k. No set-v4 vector needs ES256 regeneration (all regen
   members are Ed25519 and byte-deterministic), so this affects only
   future sets. Verification is unaffected.
4. **Component coverage is the profile's subset**: @method, @path,
   @query, @authority, @status (with ;req) and header fields. Other
   RFC 9421 derived components (@scheme, @target-uri, @query-param,
   @request-response, ...) and component parameters (;sf, ;bs, ;tr,
   ;name, ;key) raise a BASE-stage error instead of being handled.
5. **@authority default-port rule** treats port 443 as the default (the
   profile's exchanges are https, per the wimse-aud values); the message
   itself carries no scheme, so a non-https deployment would need a
   scheme-aware configuration, which v1 does not offer.
6. **WIT validation is the profile-relevant subset**: issuer signature
   against the configured anchor, exp/iat window at the verification
   time, cnf.jwk extraction. It is not a full workload-creds validation
   (no issuer allowlist beyond the anchor, no jti or audience checks on
   the token itself).
7. **Response verification requires the paired request** (CONTEXT stage
   fails without one): response judgments are defined relative to the
   request (;req components, wimse-req-nonce), so this is by design, but
   it means a bare response artifact cannot be judged.
8. **E_ALG_BINDING refinement needs known keys**: with the published test
   materials supplied (as the runner does), a signature that verifies
   under a different known key is classified CRYPTO/E_ALG_BINDING
   (N-15). Without known keys, the same artifact is classified
   CRYPTO/E_SIGNATURE_INVALID. The verdict is identical either way; only
   the layer-2 refinement differs.
9. **HTTP parsing is the wire form the profile uses**: HTTP/1.1 with CRLF
   line endings, no chunked transfer coding, no header folding. HTTP/2
   and HTTP/3 message forms are out of scope for v1.
