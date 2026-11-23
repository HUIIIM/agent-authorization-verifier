# Version skew: implementing -09 against the -08 vector set

This verifier implements **draft-ietf-wimse-http-signature-09**. The only
published test vectors (suite set v4, HUIIIM/wimse-http-signature-test-vectors)
are mapped to **draft-ietf-wimse-http-signature-08**. This document records
the -08 to -09 diff as it touches the suite's twelve stages, and classifies
every judged vector as **-09-applicable** (its published expectation holds
under -09) or **-08-only** (its expectation depends on -08 text that -09
changed). A vector that fails because the draft changed would be a skew
finding, not a code bug; as the table shows, there are none.

Method: both draft texts were read directly (IETF archive plain text).
The -09 Appendix B.1 change list is the authoritative log of what changed;
each entry below was cross-checked against the actual -08 and -09 section
text, quoted here. Everything in section 3 and sections 3.1-3.6 that is
not listed below is textually unchanged between -08 and -09 in every rule
the vectors exercise.

## The five -09 changes (Appendix B.1 of -09)

### 1. Issue #369 -- server-generated nonce from Accept-Signature [sender-side only]

-09 section 3 adds: "On a request, the client MAY use a server-generated
nonce from Accept-Signature ... instead of generating one, when that
value meets these requirements" (the uniqueness and entropy requirements,
which are unchanged: the nonce MUST be generated with a CSPRNG and MUST
contain at least 64 bits of entropy). -08 has no such sentence.

- Stages touched: none on the recipient side. This is a sender
  permission; no recipient check changes.
- Vectors affected: none. Every vector nonce is sender-generated; probe
  N-16 (nonce entropy) tests the same unchanged requirement.

### 2. Issue #419 -- CONNECT @authority follows RFC 9421 default-port omission [the one substantive clarification]

-08 section 3: "The @authority value is the host and port of the CONNECT
target (Section 2.2.3 of [RFC9421])."

-09 section 3: "The @authority value follows Section 2.2.3 of [RFC9421]
(hostname lowercased; default port omitted) and can therefore differ
from the CONNECT request target, which always includes the port."

- Stages touched: BASE (the @authority derivation) and COVERAGE (the
  CONNECT component family).
- Vectors affected: **P-04, N-02, N-21** -- the CONNECT family. All three
  are built with the RFC 9421 derivation (`@authority` = `svcb.example.com`,
  port 443 omitted), which is what -09 now states. Under a literal reading
  of -08's sentence, P-04's published signature base would have been
  defective; the suite had already corrected P-04 to the RFC 9421 value
  (its revision K1, tracking this same issue), and -09 confirms that
  construction. Classification: -09-applicable, on a clarified clause;
  they would have been the -08-only casualties had the suite followed
  -08's sentence literally.

### 3. Issue #417 -- Introduction editorial

-09 names HTTP in the opening sentence and explains why application-layer
signatures help across TLS hops. No normative content.

- Stages touched: none. Vectors affected: none.

### 4. Issue #420 -- example nonces are illustrative [editorial note]

-09 section 3.7 adds: "The nonce values in these examples are
illustrative and do not meet the entropy requirement in Section 3."
The examples themselves were not regenerated. (This is the note the
suite's observation O-2 asked the editors to add; the editors accepted
it, and it has now landed.)

- Stages touched: none (the examples are non-normative).
- Vectors affected: none.

### 5. Issue #422 -- cross-references repointed [editorial]

The WIT validation reference moves from "Section 5.1.4 of
[I-D.ietf-wimse-workload-creds]" (-08) to "Section 5.1.3" (-09), in both
places it appears (section 3 and section 3.6), and the deployment
architecture reference in section 1.1 moves from Sec. 1.2 to Section 1.1
of the same document. The referenced validation procedure is the same;
only the pointer was wrong.

- Stages touched: WIT (pointer only; the validation semantics this
  verifier implements -- issuer signature, validity window, cnf.jwk
  extraction -- are unchanged).
- Vectors affected: none.

## What did not change

The following rules are textually identical in -08 and -09 and carry the
remaining 26 judged vectors: the required request components (@method,
@path, @query, with @query = "?" when there is no query); the headers that
MUST be signed when present; the signed-response component list and its
CONNECT variant (the variant itself was introduced in -08, issue #368);
the Content-Digest requirement for messages with a body; the required
signature parameters (created, expires, nonce, tag; wimse-aud for
requests; wimse-req-nonce for responses) and the forbidden ones (keyid,
alg); selection by tag and rejection of ambiguous tags; the
wimse-aud simple-string-comparison rule (introduced in -08, issue #396);
the cnf.jwk.alg binding (section 3.1); the signed-response rules of
section 3.5; the error surface of section 3.6; and the validity-window
rejection rule.

## Per-vector applicability (29 judged vectors)

| Vector | Expectation (summary) | Applicability under -09 | Basis |
|---|---|---|---|
| P-01 | ACCEPT | -09-applicable | unchanged rules |
| P-02 | ACCEPT | -09-applicable | unchanged rules |
| P-03 | ACCEPT | -09-applicable | unchanged rules |
| P-04 | ACCEPT | -09-applicable, clarified clause | #419 (see above) |
| P-05 | ACCEPT | -09-applicable | unchanged rules |
| P-06 | ACCEPT | -09-applicable | unchanged rules |
| N-01 | REJECT COVERAGE/E_COVERAGE_MISSING | -09-applicable | unchanged rules |
| N-02 | REJECT COVERAGE/E_COVERAGE_FORBIDDEN | -09-applicable, clarified clause | #419 (CONNECT family) |
| N-03 | REJECT COVERAGE/E_DIGEST_MISSING | -09-applicable | unchanged rules |
| N-04 | REJECT DIGEST/E_DIGEST_MISMATCH | -09-applicable | unchanged rules |
| N-05 | REJECT PARAMS/E_PARAM_MISSING | -09-applicable | unchanged rules |
| N-06 | REJECT PARAMS/E_PARAM_FORBIDDEN | -09-applicable | unchanged rules |
| N-07 | REJECT PARAMS/E_PARAM_FORBIDDEN | -09-applicable | unchanged rules |
| N-08 | REJECT SELECT/E_TAG_AMBIGUOUS | -09-applicable | unchanged rules |
| N-09 | REJECT WINDOW/E_WINDOW_OUTSIDE | -09-applicable | unchanged rules (see note) |
| N-09b | ACCEPT at T0+300, REJECT WINDOW at T0+301 | -09-applicable | unchanged rules |
| N-10 | REJECT AUD/E_AUD_MISMATCH | -09-applicable | unchanged rules (#396 landed in -08) |
| N-11 | REJECT PARAMS/E_PARAM_MISSING | -09-applicable | unchanged rules |
| N-12 | CLIENT_REJECT PARAMS/E_REQNONCE_MISSING | -09-applicable | unchanged rules |
| N-13 | CLIENT_REJECT BINDING/E_REQNONCE_MISMATCH | -09-applicable | unchanged rules |
| N-14 | CLIENT_REJECT BINDING/E_RESPONSE_UNSIGNED | -09-applicable | unchanged rules |
| N-15 | REJECT CRYPTO/E_ALG_BINDING | -09-applicable | unchanged rules |
| N-16 | probe (sender entropy) | not judgeable in either version | #369 does not change the entropy requirement |
| N-17 | probe (server error surface) | not judgeable in either version | section 3.6 unchanged |
| N-18 | probe (server unsigned success) | not judgeable in either version | sections 3.5/3.6 unchanged |
| N-19 | probe (Accept-Signature strength) | not judgeable in either version | section 3.5 rule unchanged; #369 concerns nonces, not coverage |
| N-20 | probe (verifier processing order) | not judgeable in either version | WIT-first rule unchanged (#422 is a pointer fix) |
| N-21 | CLIENT_REJECT COVERAGE/E_COVERAGE_FORBIDDEN | -09-applicable, clarified clause | #419 (CONNECT family) |
| N-22 | probe (verifier selection by label) | not judgeable in either version | tag-selection rule unchanged |

**Headline: 29 of 29 judged vectors are -09-applicable; 0 are -08-only.**
Twenty-six rest on textually unchanged rules; three (P-04, N-02, N-21)
rest on the single clarified clause (#419), where -09 confirms the
suite's existing construction. The six behavior probes are not judgeable
by an artifact verifier under either version -- a scope boundary, not
skew. The three observations are unjudged in both versions; observation
O-2 is the one #420 addresses.

Note on N-09: its applicability is not in question -- the window rule is
unchanged. Its *attribution* in this verifier diverges from the published
expectation for a suite-side reason (the WIT is also expired at its
verify time), analyzed in selfcheck.md. That is neither a code bug nor
draft skew: both -08 and -09 mandate WIT validation before signature
validation, and section 3.6 forbids distinguishing which check failed in
the error response.
