# W3 gate U3: WIT pre-checks against [workload-creds] section 5.1.4

Wave S-01, W3. Gate U3 is the first step of the wave: read the current
`draft-ietf-wimse-workload-creds` section 5.1.4 in full and align it item
by item with the design document (`s01-suite-design-2026-11-13.md`)
section 3.2 WIT row. No WIT fine-detail work was started before this
gate was closed.

This file holds the three U3 artifacts for household review: the verbatim
record of the draft section, the alignment table, and the difference list.
Differences between the draft and the design row are **registered only**
and are **not implemented**; each is marked PENDING HOUSEHOLD DECISION.
The WIT module is implemented from the design section 3.2 row (see section 6).

## 1. Draft read

* Draft read: `draft-ietf-wimse-workload-creds-03`, published 30 October
  2026, expires 3 May 2027.
* Sources: <https://datatracker.ietf.org/doc/draft-ietf-wimse-workload-creds/>
  and <https://www.ietf.org/archive/id/draft-ietf-wimse-workload-creds-03.txt>.
* The previous version, `-02` (2 July 2026), had no WIT validation
  procedure at all; its section 5.1.3 was "A note on iss claim and key
  distribution".
* **The current draft has no section 5.1.4.** A search of the `-03` text
  finds no "5.1.4". Section 5.1 has three subsections: 5.1.1 The WIT
  HTTP Header, 5.1.2 Including Additional Claims, 5.1.3 Validating the
  WIT. The validation procedure the design's section 5.1.4 pointer
  intends is section 5.1.3, added in `-03` (Appendix A.1: "Add a WIT
  validation procedure for recipients (#290, #294)").

## 2. Verbatim record: section 5.1.3 "Validating the WIT"

`draft-ietf-wimse-workload-creds-03`, section 5.1.3, in full:

> Verification of a WIT follows [RFC7515] and the JWT best practices in
> [I-D.ietf-oauth-rfc8725bis], with the WIMSE-specific requirements
> below. To validate a WIT, the recipient MUST ensure the following:
>
> * The token is a single well-formed JWT using JWS compact
>   serialization ([RFC7515], [RFC7519]).
>
> * The sub claim is present and is a single Workload Identifier
>   ([WIMSE-ID], Section 4). The recipient uses the trust domain of
>   that identifier to select the configured trust anchors
>   (Section 3).
>
> * The typ JOSE header parameter conveys a media type of wit+jwt.
>
> * The JWS signature is valid under those trust anchors, as described
>   in Section 3.
>
> * The cnf claim is present and contains a jwk object with an alg
>   member as specified in Section 5.1.
>
> * Additional claims that are not understood are ignored, as
>   specified in Section 5.1.2.
>
> See Section 9.3.1 for WIT lifetime considerations.

## 3. Supporting points from the same draft

* Section 5.1 (WIT content). The WIT is a JWS with registered claims.
  The `alg` header identifies the JWS asymmetric signature algorithm;
  the `none` algorithm MUST NOT be used. The `typ` header carries the
  `wit+jwt` media type. The `iss` claim is RECOMMENDED but OPTIONAL.
  The `sub` claim MUST be present and MUST be a single Workload
  Identifier, constrained to exactly one per credential. The `exp` claim
  is the expiration time (RFC 7519 section 4.1.4); "WITs should be
  refreshed regularly, e.g., on the order of hours." The `jti` claim is
  OPTIONAL. The `cnf` claim MUST be present and MUST contain a `jwk`
  object with the workload public key (RFC 7800 section 3.2); the `alg`
  member within the `jwk` object MUST be present; the presented proof
  MUST be produced with the algorithm identified by that `alg` member;
  the `none` algorithm and symmetric-key algorithms MUST NOT be used;
  general purpose implementations MUST support ES256.
* Section 3 (trust anchors). "To validate a WIT, the receiving workload
  verifies the JWS signature using key material from the trust anchors
  configured for the trust domain in the sub claim." Anchor material
  MAY hold more than one public key for rotation. If the JWS header
  contains a `kid`, the validator uses the anchor key with the same
  `kid` value; if `kid` is absent, deployment policy must provide
  unambiguous key selection (for example, when only a single key is
  configured for that trust domain). The draft defines no mechanism for
  discovering trust anchor information.
* Section 9.3.1 (WIT lifetime). "The WIT MUST have a limited lifetime
  expressed through the exp claim. If both a WIT and its corresponding
  private key are compromised, an attacker can impersonate the workload
  until the WIT expires." The draft defines no revocation mechanism
  for WITs and does not rely on one.
* Section 5.3 (error conditions). If WIT validation fails for any
  reason, the failure may be reported with RFC 9457 problem details;
  HTTP 401 is allowed for WIT errors when a WWW-Authenticate mechanism
  exists. The draft enumerates no per-failure error codes.

## 4. Design section 3.2 WIT row (verbatim)

`s01-suite-design-2026-11-13.md` section 3.2, WIT row, quoted verbatim:

> WIT 先验：JWS 验签（Issuer 信任锚，RFC 7515）；typ＝wit+jwt 核；exp＞验证时刻（RFC 7519 §4.1.4）；取 cnf.jwk 为唯一验签密钥源（RFC 7800 §3.1）；细则按 [workload-creds] §5.1.4。输入：WIT 字面＋Issuer 锚＋时刻。输出：绑定密钥 JWK＋sub；失败→E_WIT_SIG／E_WIT_TYPE／E_WIT_EXP／E_WIT_CNF。

## 5. Alignment table

| Design section 3.2 item | Draft point (`-03`) | Verdict |
| --- | --- | --- |
| JWS signature verified under the Issuer trust anchor (RFC 7515) | Section 5.1.3: "The JWS signature is valid under those trust anchors, as described in Section 3"; section 3 gives the anchor-selection rules | Aligned |
| `typ` must be `wit+jwt` | Section 5.1.3: "The typ JOSE header parameter conveys a media type of wit+jwt"; section 5.1 repeats it | Aligned |
| `exp` must be after the verification moment (RFC 7519 section 4.1.4) | Section 5.1.3 does NOT list an exp-vs-now check; section 5.1 requires `exp` present; section 9.3.1 requires a limited lifetime expressed through `exp` | Difference D2 (registered only) |
| `cnf.jwk` is the sole binding-key source (RFC 7800 section 3.1) | Section 5.1.3: "The cnf claim is present and contains a jwk object with an alg member as specified in Section 5.1" | Aligned |
| Fine detail follows [workload-creds] section 5.1.4 | The current draft has no section 5.1.4; the validation procedure is section 5.1.3 | Difference D1 (registered only) |
| Failure codes E_WIT_SIG / E_WIT_TYPE / E_WIT_EXP / E_WIT_CNF | The draft enumerates no per-failure codes (section 5.3 points at RFC 9457 problem details) | Design-level taxonomy; no draft conflict |
| Input: WIT literal + Issuer anchor + moment; output: binding key JWK + sub | Section 5.1.3 selects anchors from the trust domain of the `sub` claim; output is not specified by the draft | Difference D4 (registered only) |
| Unknown claims | Section 5.1.3: "Additional claims that are not understood are ignored, as specified in Section 5.1.2" | Aligned |

## 6. Difference list (registered only, NOT implemented)

Each item below is a difference between the draft (`-03`) and the design
section 3.2 row. None of them was implemented in W3. Each is marked
PENDING HOUSEHOLD DECISION (候户裁) for the household to rule on.

* D1 - Section pointer. The design row cites [workload-creds] section
  5.1.4; the current draft has no section 5.1.4 (nor did `-02`). The
  validation procedure is section 5.1.3 in `-03`. PENDING HOUSEHOLD
  DECISION: correct the design pointer to section 5.1.3, or confirm the
  intended draft version.
* D2 - Expiry comparison. The design row requires `exp` after the
  verification moment (RFC 7519 section 4.1.4). Draft section 5.1.3's
  MUST list does not include an `exp`-vs-now check; it only points at
  section 9.3.1 (limited lifetime expressed through `exp`). The WIT
  module keeps the design row's `exp` check. PENDING HOUSEHOLD
  DECISION: confirm the `exp` comparison stays a mandatory validation
  step despite the draft's silence.
* D3 - Anchor selection by `sub`. The draft (sections 5.1.3 and 3)
  requires `sub` present as a single Workload Identifier and selects
  trust anchors from that identifier's trust domain. The design row
  takes a single configured Issuer anchor as input and does not
  validate `sub` presence or format. The WIT module keeps the single
  configured anchor and does not add `sub` validation. PENDING
  HOUSEHOLD DECISION: whether anchor selection by `sub` trust domain
  is required.
* D4 - Malformed tokens. The draft requires a single well-formed JWT
  in JWS compact serialization. The design row's failure codes name no
  malformed code; the WIT module reports an unparseable token as
  `E_WIT_SIG` (the JWS cannot be verified). PENDING HOUSEHOLD
  DECISION: confirm the `E_WIT_SIG` mapping, or add a distinct code.
* D5 - Error reporting. Draft section 5.3 points at RFC 9457 problem
  details and allows HTTP 401 for WIT errors; it enumerates no
  per-failure codes. The verifier's `E_WIT_*` codes are a design-level
  taxonomy for an offline verifier. No action proposed; recorded for
  completeness. PENDING HOUSEHOLD DECISION: none needed unless the
  household wants an HTTP mapping.

## 7. What W3 implements (from the design row, not from the draft)

* The four failure codes of the design row: `E_WIT_SIG` (JWS signature
  or structure), `E_WIT_TYPE` (`typ` is not `wit+jwt`), `E_WIT_EXP`
  (`exp` missing, not an integer, or not after the verification
  moment), `E_WIT_CNF` (`cnf.jwk` missing, not an object, or without
  an `alg` member). The previous codes `E_WIT_SIGNATURE`,
  `E_WIT_EXPIRED`, `E_WIT_CNF_MISSING`, `E_WIT_MALFORMED` are retired.
* The `typ` check, which the design row requires but the previous
  implementation did not perform.
* The pre-existing `iat` (issued-at) check is removed: neither the
  design row nor draft section 5.1.3 mentions `iat`, so it is outside
  the section 3.2 scope. This is an alignment to the design row, not a
  draft difference.
* The `cnf.jwk` `alg`-member requirement of draft sections 5.1 and
  5.1.3 was already enforced by the previous implementation and stays
  enforced; it is aligned, not a difference.
* Unsupported signature algorithms (including `none` and symmetric
  algorithms) fail signature verification and are reported as
  `E_WIT_SIG`; there is no separate check, matching the design row.
