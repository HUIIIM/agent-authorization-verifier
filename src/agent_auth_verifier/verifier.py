"""The WIMSE HTTP signature verification core.

Implements the recipient-side verification procedure of
draft-ietf-wimse-http-signature-09 section 3 (which is textually identical
to -08 in every rule exercised here; see SKEW.md) as a twelve-stage
pipeline whose stage codes are the test vector suite's, verbatim and in
suite order:

    CONTEXT, PARSE, WIT, SELECT, PARAMS, COVERAGE, BASE, DIGEST, CRYPTO,
    AUD, BINDING, WINDOW

Two-layer result model, aligned with the suite:

* Layer 1 -- the artifact-level verdict: ACCEPT, REJECT (a request the
  server refuses, section 3.6 surface), or CLIENT_REJECT (a response the
  client refuses, sections 3.4/3.5).
* Layer 2 -- the failure classification: the first failing stage and its
  code, the full per-stage record, and any later stages that also fail
  (cascades). A stage whose inputs are unavailable because an earlier stage
  failed is reported "blocked", not failed; a stage that does not apply to
  the message kind is "skip".

The WIT is validated before the message signature (section 3), the
signature algorithm and key come only from the WIT cnf.jwk binding
(section 3.1), the signature is selected by its tag parameter, never by
label (section 3), and wimse-aud is compared with the trusted configuration
by RFC 3986 simple string comparison (section 3.2). No network access.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from .components import ComponentError, build_signature_base, component_name, is_req
from .crypto import jwk_to_public_key, verify_signature
from .httpmsg import HttpMessage, MessageParseError, parse_message
from .sf import (
    SFBytes,
    SFInnerList,
    SFItem,
    SFMember,
    SFParseError,
    SFString,
    parse_dictionary,
)
from .wit import WitError, WitInfo, validate_wit

STAGE_ORDER = [
    "CONTEXT",
    "PARSE",
    "WIT",
    "SELECT",
    "PARAMS",
    "COVERAGE",
    "BASE",
    "DIGEST",
    "CRYPTO",
    "AUD",
    "BINDING",
    "WINDOW",
]

WIMSE_TAG = "wimse-workload-to-workload"
PROBLEM_TYPE_URI = "https://iana.org/assignments/http-problem-types#wimse-signature-invalid"

# Header fields the profile requires to be signed when present (section 3).
SIGN_WHEN_PRESENT = [
    "content-type",
    "content-digest",
    "authorization",
    "txn-token",
    "workload-identity-token",
]

REQUIRED_PARAMS = ["created", "expires", "nonce", "tag"]
FORBIDDEN_PARAMS = ["keyid", "alg"]


@dataclass
class TrustedConfig:
    """Recipient-side trusted configuration: the wimse-aud audience values
    this recipient accepts, and the WIT issuer trust anchor JWK."""

    trusted_audiences: list[str]
    issuer_anchor_jwk: dict


@dataclass
class KnownKey:
    """A key the caller knows about (for example the published test
    materials), used only to refine CRYPTO failure classification: if a
    signature fails under the cnf-bound key but verifies under a different
    known key/algorithm, the failure is an algorithm-binding failure
    (section 3.1), not a plain invalid signature."""

    name: str
    alg: str
    public_jwk: dict


@dataclass
class StageResult:
    stage: str
    status: str  # "pass", "fail", "skip", "blocked"
    code: str | None = None
    detail: str = ""


@dataclass
class Judgment:
    verdict: str  # "ACCEPT", "REJECT", or "CLIENT_REJECT"
    role: str  # "server" for requests, "client" for responses
    failing_stage: str | None = None
    failing_code: str | None = None
    cascades: list[str] = field(default_factory=list)
    stages: list[StageResult] = field(default_factory=list)
    selected_label: str | None = None
    signature_base: str | None = None
    wit_subject: str | None = None
    notes: list[str] = field(default_factory=list)

    def stage(self, name: str) -> StageResult | None:
        for result in self.stages:
            if result.stage == name:
                return result
        return None

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "role": self.role,
            "failing_stage": self.failing_stage,
            "failing_code": self.failing_code,
            "cascades": self.cascades,
            "selected_label": self.selected_label,
            "wit_subject": self.wit_subject,
            "signature_base": self.signature_base,
            "notes": self.notes,
            "stages": [
                {
                    "stage": s.stage,
                    "status": s.status,
                    "code": s.code,
                    "detail": s.detail,
                }
                for s in self.stages
            ],
        }


def _param_string(params: dict, name: str) -> str | None:
    value = params.get(name)
    if isinstance(value, SFString):
        return value.value
    return None


def _member_tag(member: SFMember) -> str | None:
    return _param_string(member.params, "tag")


def _sign_response_required(request: HttpMessage) -> bool:
    """Section 3.3/3.5: the request asked for a signed response if its
    WIMSE signature carries wimse-sign-response with the value true (a bare
    parameter name means true in RFC 8941)."""
    raw = request.header("signature-input")
    if raw is None:
        return False
    try:
        members = parse_dictionary(raw)
    except SFParseError:
        return False
    for member in members.values():
        if _member_tag(member) == WIMSE_TAG:
            return member.params.get("wimse-sign-response") is True
    return False


class Verifier:
    def __init__(
        self,
        config: TrustedConfig,
        known_keys: list[KnownKey] | None = None,
    ) -> None:
        self.config = config
        self.known_keys = known_keys or []

    # -- stage bookkeeping -------------------------------------------------
    def _record(
        self,
        results: dict[str, StageResult],
        stage: str,
        status: str,
        code: str | None = None,
        detail: str = "",
    ) -> None:
        results[stage] = StageResult(stage=stage, status=status, code=code, detail=detail)

    def _fail(
        self,
        results: dict[str, StageResult],
        stage: str,
        code: str,
        detail: str,
    ) -> None:
        self._record(results, stage, "fail", code, detail)

    # -- main entry point --------------------------------------------------
    def verify(
        self,
        raw_message: str,
        verify_time: int,
        paired_request_raw: str | None = None,
        expected_base: dict[str, str] | None = None,
    ) -> Judgment:
        results: dict[str, StageResult] = {}
        notes: list[str] = []

        # CONTEXT: parse the artifact (and the paired request, for responses).
        try:
            message = parse_message(raw_message)
        except MessageParseError as exc:
            self._fail(results, "CONTEXT", exc.code, str(exc))
            return self._assemble(results, "server", notes)
        role = "server" if message.kind == "request" else "client"
        paired: HttpMessage | None = None
        if message.kind == "response":
            if paired_request_raw is None:
                self._fail(
                    results,
                    "CONTEXT",
                    "E_CONTEXT_PAIRED_REQUEST_MISSING",
                    "response verification is defined relative to the request "
                    "(;req components, wimse-req-nonce binding); no paired request given",
                )
                return self._assemble(results, role, notes)
            try:
                paired = parse_message(paired_request_raw)
            except MessageParseError as exc:
                self._fail(results, "CONTEXT", "E_CONTEXT_PAIRED_MALFORMED", str(exc))
                return self._assemble(results, role, notes)
            if paired.kind != "request":
                self._fail(
                    results,
                    "CONTEXT",
                    "E_CONTEXT_PAIRED_MALFORMED",
                    "paired message is not a request",
                )
                return self._assemble(results, role, notes)
        self._record(results, "CONTEXT", "pass", detail=f"{message.kind} artifact")

        # PARSE: Signature-Input / Signature dictionaries.
        sig_input: dict[str, SFMember] = {}
        sig_values: dict[str, bytes] = {}
        parse_detail = ""
        try:
            raw_input = message.header("signature-input")
            if raw_input is not None:
                sig_input = parse_dictionary(raw_input)
            raw_sig = message.header("signature")
            if raw_sig is not None:
                for label, member in parse_dictionary(raw_sig).items():
                    if isinstance(member, SFItem) and isinstance(member.value, SFBytes):
                        sig_values[label] = member.value.value
                    else:
                        raise SFParseError(f"Signature member {label!r} is not a byte sequence")
            parse_detail = f"{len(sig_input)} signature member(s)"
            self._record(results, "PARSE", "pass", detail=parse_detail)
        except SFParseError as exc:
            self._fail(results, "PARSE", "E_PARSE_SIGNATURE_HEADERS", str(exc))

        # WIT: validated before the message signature (section 3).
        wit_info: WitInfo | None = None
        token = message.header("workload-identity-token")
        if "PARSE" in results and results["PARSE"].status == "fail":
            self._record(results, "WIT", "blocked", detail="signature headers unparsable")
        elif token is None:
            self._fail(results, "WIT", "E_WIT_MISSING", "no Workload-Identity-Token header")
        else:
            try:
                wit_info = validate_wit(token, self.config.issuer_anchor_jwk, verify_time)
                self._record(
                    results,
                    "WIT",
                    "pass",
                    detail=f"sub={wit_info.subject} cnf alg={wit_info.alg} kid={wit_info.kid}",
                )
            except WitError as exc:
                self._fail(results, "WIT", exc.code, exc.detail)

        # Unsigned-response branch (section 3.5): no signature members at all.
        if message.kind == "response" and not sig_input:
            assert paired is not None
            for stage in ("SELECT", "PARAMS", "COVERAGE", "BASE", "DIGEST", "CRYPTO", "AUD"):
                self._record(results, stage, "skip", detail="response carries no signature")
            if _sign_response_required(paired):
                self._fail(
                    results,
                    "BINDING",
                    "E_RESPONSE_UNSIGNED",
                    "request carried wimse-sign-response=true but the response is unsigned",
                )
            else:
                self._record(
                    results,
                    "BINDING",
                    "pass",
                    detail="unsigned response; signed response was not required",
                )
                notes.append(
                    "unsigned response accepted: the request did not require a signed "
                    "response (section 3.5 opportunistic case)"
                )
            self._record(results, "WINDOW", "skip", detail="no signature window to check")
            judgment = self._assemble(results, role, notes)
            judgment.wit_subject = wit_info.subject if wit_info else None
            return judgment

        # SELECT: choose the WIMSE signature by tag, never by label (section 3).
        selected_label: str | None = None
        selected: SFInnerList | None = None
        candidates = [
            label for label, member in sig_input.items() if _member_tag(member) == WIMSE_TAG
        ]
        if results["PARSE"].status == "fail":
            self._record(results, "SELECT", "blocked", detail="signature headers unparsable")
        elif len(candidates) > 1:
            self._fail(
                results,
                "SELECT",
                "E_TAG_AMBIGUOUS",
                f"{len(candidates)} signatures carry tag={WIMSE_TAG!r}: {candidates}",
            )
        elif len(candidates) == 0:
            if message.kind == "response":
                assert paired is not None
                if _sign_response_required(paired):
                    self._record(
                        results, "SELECT", "skip", detail="no WIMSE-tagged signature present"
                    )
                    for stage in ("PARAMS", "COVERAGE", "BASE", "DIGEST", "CRYPTO", "AUD"):
                        self._record(results, stage, "skip", detail="no WIMSE signature")
                    self._fail(
                        results,
                        "BINDING",
                        "E_RESPONSE_UNSIGNED",
                        "request required a signed response; response has no WIMSE signature",
                    )
                    self._record(results, "WINDOW", "skip", detail="no WIMSE signature")
                    judgment = self._assemble(results, role, notes)
                    judgment.wit_subject = wit_info.subject if wit_info else None
                    return judgment
                notes.append("response carries signatures but none is a WIMSE signature")
                self._fail(
                    results,
                    "SELECT",
                    "E_NO_WIMSE_SIGNATURE",
                    "no signature member carries the WIMSE tag",
                )
            else:
                self._fail(
                    results,
                    "SELECT",
                    "E_NO_WIMSE_SIGNATURE",
                    "no signature member carries the WIMSE tag",
                )
        else:
            selected_label = candidates[0]
            member = sig_input[selected_label]
            if not isinstance(member, SFInnerList):
                self._fail(
                    results,
                    "SELECT",
                    "E_SIGNATURE_MALFORMED",
                    "signature member is not an inner list",
                )
            elif selected_label not in sig_values:
                self._fail(
                    results,
                    "SELECT",
                    "E_SIGNATURE_MISSING",
                    f"no Signature value for label {selected_label!r}",
                )
            else:
                selected = member
                self._record(
                    results, "SELECT", "pass", detail=f"tag match on label {selected_label!r}"
                )

        params: dict = selected.params if selected is not None else {}

        # PARAMS: required and forbidden signature parameters (section 3).
        if selected is None:
            self._record(results, "PARAMS", "blocked", detail="no signature selected")
        else:
            missing = [name for name in REQUIRED_PARAMS if name not in params]
            if message.kind == "request" and "wimse-aud" not in params:
                missing.append("wimse-aud")
            forbidden = [name for name in FORBIDDEN_PARAMS if name in params]
            if message.kind == "response" and "wimse-req-nonce" not in params:
                self._fail(
                    results,
                    "PARAMS",
                    "E_REQNONCE_MISSING",
                    "signed response does not carry wimse-req-nonce (section 3.4)",
                )
            elif missing:
                self._fail(
                    results,
                    "PARAMS",
                    "E_PARAM_MISSING",
                    f"required parameter(s) missing: {', '.join(missing)}",
                )
            elif forbidden:
                self._fail(
                    results,
                    "PARAMS",
                    "E_PARAM_FORBIDDEN",
                    f"parameter(s) that MUST NOT be used are present: {', '.join(forbidden)}",
                )
            elif not isinstance(params.get("created"), int) or not isinstance(
                params.get("expires"), int
            ):
                self._fail(
                    results,
                    "PARAMS",
                    "E_PARAM_MALFORMED",
                    "created/expires are not integers",
                )
            else:
                self._record(results, "PARAMS", "pass")

        # COVERAGE: the profile's required and forbidden component sets.
        if selected is None:
            self._record(results, "COVERAGE", "blocked", detail="no signature selected")
        else:
            self._check_coverage(results, message, paired, selected)

        # BASE: construct the signature base; compare with a provided base
        # when the caller supplies one (the vector runner does).
        signature_base: str | None = None
        if selected is None:
            self._record(results, "BASE", "blocked", detail="no signature selected")
        else:
            try:
                signature_base = build_signature_base(message, selected, paired)
            except ComponentError as exc:
                # A hard failure, never "blocked": a base that cannot be built
                # must reject the artifact (RFC 9421 Section 2.5: errors fail the
                # algorithm). Recording it as blocked would let the verdict fall
                # through to ACCEPT with CRYPTO never run.
                self._fail(results, "BASE", exc.code, exc.detail)
            else:
                if expected_base is not None and selected_label in expected_base:
                    if signature_base == expected_base[selected_label]:
                        self._record(results, "BASE", "pass", detail="matches provided base")
                    else:
                        self._fail(
                            results,
                            "BASE",
                            "E_BASE_MISMATCH",
                            "constructed signature base differs from the provided base",
                        )
                else:
                    self._record(results, "BASE", "pass", detail="base constructed")

        # DIGEST: recompute Content-Digest over the received body (section 3).
        digest_value = message.header("content-digest")
        if digest_value is None:
            self._record(results, "DIGEST", "skip", detail="no Content-Digest header to verify")
        else:
            self._check_digest(results, message, digest_value)

        # CRYPTO: verify with the cnf-bound algorithm and key only (section 3.1).
        if wit_info is None:
            self._record(results, "CRYPTO", "blocked", detail="no validated WIT key binding")
        elif signature_base is None or selected_label is None:
            self._record(results, "CRYPTO", "blocked", detail="no signature base")
        else:
            signature = sig_values[selected_label]
            try:
                bound_key = jwk_to_public_key(wit_info.cnf_jwk)
            except ValueError as exc:
                self._fail(results, "CRYPTO", "E_ALG_UNSUPPORTED", str(exc))
            else:
                if verify_signature(wit_info.alg, bound_key, signature, signature_base.encode()):
                    self._record(
                        results,
                        "CRYPTO",
                        "pass",
                        detail=f"verified with cnf-bound {wit_info.alg} key {wit_info.kid}",
                    )
                else:
                    code = "E_SIGNATURE_INVALID"
                    detail = "signature does not verify under the cnf-bound key"
                    for known in self.known_keys:
                        if known.public_jwk == wit_info.cnf_jwk:
                            continue
                        try:
                            other_key = jwk_to_public_key(known.public_jwk)
                        except ValueError:
                            continue
                        if verify_signature(
                            known.alg, other_key, signature, signature_base.encode()
                        ):
                            code = "E_ALG_BINDING"
                            detail = (
                                f"signature verifies under {known.name} ({known.alg}) but the "
                                f"WIT cnf binds {wit_info.alg}/{wit_info.kid} (section 3.1)"
                            )
                            break
                    self._fail(results, "CRYPTO", code, detail)

        # AUD: simple string comparison against trusted audiences (section 3.2).
        if message.kind == "response":
            self._record(results, "AUD", "skip", detail="responses carry no wimse-aud")
        elif selected is None:
            self._record(results, "AUD", "blocked", detail="no signature selected")
        else:
            aud = _param_string(params, "wimse-aud")
            if aud is None:
                self._record(results, "AUD", "blocked", detail="no wimse-aud parameter")
            elif aud in self.config.trusted_audiences:
                self._record(results, "AUD", "pass", detail=f"audience {aud!r} is trusted")
            else:
                self._fail(
                    results,
                    "AUD",
                    "E_AUD_MISMATCH",
                    f"wimse-aud {aud!r} is not in the trusted configuration "
                    "(simple string comparison, no normalization)",
                )

        # BINDING: response wimse-req-nonce equals the request nonce (section 3.5).
        if message.kind == "request":
            self._record(results, "BINDING", "skip", detail="requests have no req-nonce binding")
        elif selected is None or paired is None:
            self._record(results, "BINDING", "blocked", detail="no selected signature or request")
        else:
            req_nonce = self._paired_request_nonce(paired)
            resp_nonce = _param_string(params, "wimse-req-nonce")
            if req_nonce is None or resp_nonce is None:
                self._record(
                    results, "BINDING", "blocked", detail="nonce not available on one side"
                )
            elif req_nonce == resp_nonce:
                self._record(
                    results, "BINDING", "pass", detail="wimse-req-nonce matches request nonce"
                )
            else:
                self._fail(
                    results,
                    "BINDING",
                    "E_REQNONCE_MISMATCH",
                    "wimse-req-nonce does not equal the nonce of the corresponding request",
                )

        # WINDOW: the verification time must lie in [created, expires].
        created = params.get("created")
        expires = params.get("expires")
        if selected is None:
            self._record(results, "WINDOW", "blocked", detail="no signature selected")
        elif not isinstance(created, int) or not isinstance(expires, int):
            self._record(results, "WINDOW", "blocked", detail="created/expires unavailable")
        elif created <= verify_time <= expires:
            self._record(
                results, "WINDOW", "pass", detail=f"{verify_time} in [{created}, {expires}]"
            )
        else:
            self._fail(
                results,
                "WINDOW",
                "E_WINDOW_OUTSIDE",
                f"verification time {verify_time} outside [{created}, {expires}]",
            )

        judgment = self._assemble(results, role, notes)
        judgment.selected_label = selected_label
        judgment.signature_base = signature_base
        judgment.wit_subject = wit_info.subject if wit_info else None
        return judgment

    # -- helpers -------------------------------------------------------------
    def _check_coverage(
        self,
        results: dict[str, StageResult],
        message: HttpMessage,
        paired: HttpMessage | None,
        selected: SFInnerList,
    ) -> None:
        covered: set[tuple[str, bool]] = set()
        for item in selected.items:
            try:
                covered.add((component_name(item), is_req(item)))
            except ComponentError as exc:
                self._fail(results, "COVERAGE", "E_COMPONENT_MALFORMED", str(exc))
                return
        required: set[tuple[str, bool]] = set()
        forbidden: set[tuple[str, bool]] = set()
        if message.kind == "request":
            if message.method == "CONNECT":
                required |= {("@method", False), ("@authority", False)}
                forbidden |= {("@path", False), ("@query", False)}
            else:
                required |= {("@method", False), ("@path", False), ("@query", False)}
        else:
            required.add(("@status", False))
            paired_method = paired.method if paired is not None else None
            if paired_method == "CONNECT":
                required |= {("@method", True), ("@authority", True)}
                forbidden |= {("@path", True), ("@query", True)}
            else:
                required |= {("@method", True), ("@path", True), ("@query", True)}
        for header_name in SIGN_WHEN_PRESENT:
            if message.has_header(header_name):
                required.add((header_name, False))
        missing = sorted(required - covered)
        forbidden_hit = sorted(forbidden & covered)
        if len(message.body) > 0 and not message.has_header("content-digest"):
            self._fail(
                results,
                "COVERAGE",
                "E_DIGEST_MISSING",
                "message has a body but no Content-Digest header (section 3)",
            )
        elif missing:
            names = ", ".join(f"{name};req" if req else name for name, req in missing)
            self._fail(
                results,
                "COVERAGE",
                "E_COVERAGE_MISSING",
                f"required component(s) not signed: {names}",
            )
        elif forbidden_hit:
            names = ", ".join(f"{name};req" if req else name for name, req in forbidden_hit)
            self._fail(
                results,
                "COVERAGE",
                "E_COVERAGE_FORBIDDEN",
                f"component(s) that MUST NOT be signed are signed: {names}",
            )
        else:
            self._record(results, "COVERAGE", "pass", detail=f"{len(covered)} component(s) covered")

    def _check_digest(
        self, results: dict[str, StageResult], message: HttpMessage, digest_value: str
    ) -> None:
        try:
            members = parse_dictionary(digest_value)
        except SFParseError as exc:
            self._fail(results, "DIGEST", "E_DIGEST_MALFORMED", str(exc))
            return
        checked = False
        for alg, member in members.items():
            if not isinstance(member, SFItem) or not isinstance(member.value, SFBytes):
                self._fail(
                    results, "DIGEST", "E_DIGEST_MALFORMED", "digest value is not a byte sequence"
                )
                return
            if alg == "sha-256":
                actual = hashlib.sha256(message.body).digest()
            elif alg == "sha-512":
                actual = hashlib.sha512(message.body).digest()
            else:
                continue
            checked = True
            if actual != member.value.value:
                self._fail(
                    results,
                    "DIGEST",
                    "E_DIGEST_MISMATCH",
                    f"recomputed {alg} digest of the received body does not match the header",
                )
                return
        if checked:
            self._record(results, "DIGEST", "pass", detail="body digest matches header")
        else:
            self._record(results, "DIGEST", "skip", detail="no supported digest algorithm present")

    def _paired_request_nonce(self, paired: HttpMessage) -> str | None:
        raw = paired.header("signature-input")
        if raw is None:
            return None
        try:
            members = parse_dictionary(raw)
        except SFParseError:
            return None
        for member in members.values():
            if _member_tag(member) == WIMSE_TAG:
                return _param_string(member.params, "nonce")
        return None

    def _assemble(self, results: dict[str, StageResult], role: str, notes: list[str]) -> Judgment:
        stages = [results[name] for name in STAGE_ORDER if name in results]
        failures = [s for s in stages if s.status == "fail"]
        if failures:
            first = failures[0]
            verdict = "REJECT" if role == "server" else "CLIENT_REJECT"
            return Judgment(
                verdict=verdict,
                role=role,
                failing_stage=first.stage,
                failing_code=first.code,
                cascades=[s.stage for s in failures[1:]],
                stages=stages,
                notes=notes,
            )
        return Judgment(verdict="ACCEPT", role=role, stages=stages, notes=notes)
