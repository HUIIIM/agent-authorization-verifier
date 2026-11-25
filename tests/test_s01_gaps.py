"""S-01 gap fixes D-1..D-5 at the component / message level.

D-1 duplicate covered components, D-2 ;req misuse as a hard ComponentError
(never a fallback to the other message), D-3 obs-fold rejection, D-4 the
final non-ASCII check, D-5 the scheme-parameterized @authority default
port with the two-level scheme rule (explicit artifact scheme wins,
otherwise the profile default https).
"""

from __future__ import annotations

import pytest

from agent_auth_verifier.components import (
    DEFAULT_PORTS,
    E_BASE_DUPLICATE_COMPONENT,
    E_BASE_NON_ASCII,
    E_BASE_REQ_MISUSE,
    PROFILE_DEFAULT_SCHEME,
    ComponentError,
    _authority_value,
    artifact_scheme,
    build_signature_base,
    component_value,
    derived_value,
    resolve_scheme,
)
from agent_auth_verifier.httpmsg import MessageParseError, parse_message
from agent_auth_verifier.sf import SFInnerList, SFItem, SFString
from agent_auth_verifier.vectors import VectorSet

REQUEST = "GET /p?x=1 HTTP/1.1\r\nHost: svc.example\r\nX-A: 1\r\n\r\n"
RESPONSE = "HTTP/1.1 200 OK\r\nX-A: resp\r\n\r\n"


def _item(name: str, **params) -> SFItem:
    return SFItem(value=SFString(name), params=dict(params))


def _member(*items: SFItem) -> SFInnerList:
    return SFInnerList(items=list(items), params={"created": 1})


# -- D-1 ---------------------------------------------------------------------
def test_d1_duplicate_component_rejected() -> None:
    req = parse_message(REQUEST)
    with pytest.raises(ComponentError) as info:
        build_signature_base(req, _member(_item("x-a"), _item("@method"), _item("x-a")), None)
    assert info.value.code == E_BASE_DUPLICATE_COMPONENT


def test_d1_same_name_different_parameters_is_not_a_duplicate() -> None:
    """RFC 9421 Section 2.5 step 2.1 compares the identifier *including*
    its parameters: "x-a" and "x-a";req are distinct components."""
    req = parse_message(REQUEST)
    resp = parse_message(RESPONSE)
    base = build_signature_base(resp, _member(_item("x-a"), _item("x-a", req=True)), req)
    assert base.split("\n")[:2] == ['"x-a": resp', '"x-a";req: 1']


# -- D-2 ---------------------------------------------------------------------
def test_d2_req_on_request_with_context_supplied_is_hard_error() -> None:
    """The constructed reproducer: a request, with a context message handed
    in anyway. Before S-01 this silently took the value from that message."""
    req = parse_message(REQUEST)
    with pytest.raises(ComponentError) as info:
        component_value(_item("@method", req=True), req, paired_request=req)
    assert info.value.code == E_BASE_REQ_MISUSE
    with pytest.raises(ComponentError) as info:
        build_signature_base(req, _member(_item("@method", req=True)), req)
    assert info.value.code == E_BASE_REQ_MISUSE


def test_d2_req_on_request_without_context_is_hard_error() -> None:
    req = parse_message(REQUEST)
    with pytest.raises(ComponentError) as info:
        component_value(_item("x-a", req=True), req, paired_request=None)
    assert info.value.code == E_BASE_REQ_MISUSE


@pytest.mark.parametrize("bad", [False, 1, SFString("true")])
def test_d2_req_with_non_boolean_true_value_is_hard_error(bad: object) -> None:
    req = parse_message(REQUEST)
    resp = parse_message(RESPONSE)
    with pytest.raises(ComponentError) as info:
        component_value(_item("x-a", req=bad), resp, paired_request=req)
    assert info.value.code == E_BASE_REQ_MISUSE


def test_d2_req_on_response_without_paired_request_is_hard_error() -> None:
    resp = parse_message(RESPONSE)
    with pytest.raises(ComponentError) as info:
        component_value(_item("x-a", req=True), resp, paired_request=None)
    assert info.value.code == E_BASE_REQ_MISUSE


def test_d2_req_with_paired_message_that_is_not_a_request_is_hard_error() -> None:
    resp = parse_message(RESPONSE)
    with pytest.raises(ComponentError) as info:
        component_value(_item("x-a", req=True), resp, paired_request=resp)
    assert info.value.code == E_BASE_REQ_MISUSE


@pytest.mark.parametrize("name", ["@method", "@path", "@query", "@authority", "x-only-on-request"])
def test_d2_no_fallback_from_response_to_paired_request(name: str) -> None:
    """Without ;req the context is the response itself. A component the
    response cannot supply is an error; it is never fetched from the
    paired request instead."""
    req = parse_message("GET /p HTTP/1.1\r\nHost: svc.example\r\nX-Only-On-Request: r\r\n\r\n")
    resp = parse_message(RESPONSE)
    with pytest.raises(ComponentError):
        component_value(_item(name), resp, paired_request=req)


def test_d2_valid_req_on_response_reads_the_paired_request() -> None:
    req = parse_message(REQUEST)
    resp = parse_message(RESPONSE)
    assert component_value(_item("@method", req=True), resp, req) == "GET"
    assert component_value(_item("x-a", req=True), resp, req) == "1"
    assert component_value(_item("x-a"), resp, req) == "resp"


def test_d2_verifier_rejects_req_misuse_on_response(vector_set: VectorSet, verifier) -> None:
    """End to end on suite P-02 (a signed response): turn its
    "@method";req into "@method";req=?0. Hard BASE failure."""
    artifact = vector_set.construct("P-02")
    mutated = artifact.message_raw.replace('"@method";req', '"@method";req=?0', 1)
    assert mutated != artifact.message_raw
    judgment = verifier.verify(mutated, 1795000060, paired_request_raw=artifact.paired_raw)
    assert judgment.verdict == "CLIENT_REJECT"
    assert judgment.stage("BASE").status == "fail"
    assert judgment.stage("BASE").code == E_BASE_REQ_MISUSE


# -- D-3 ---------------------------------------------------------------------
@pytest.mark.parametrize(
    "raw",
    [
        "GET / HTTP/1.1\r\nHost: a\r\nX-A: one\r\n two\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\nX-A: one\r\n\ttwo\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\nX-A: one\r\n x-b: looks-like-a-field\r\n\r\n",
        "GET / HTTP/1.1\r\n Host: a\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\nX-A: one\n two\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\nX-A: one\rtwo\r\n\r\n",
    ],
)
def test_d3_obs_fold_rejected(raw: str) -> None:
    with pytest.raises(MessageParseError) as info:
        parse_message(raw)
    assert info.value.code == "E_CONTEXT_OBS_FOLD"


def test_d3_folded_paired_request_rejected(vector_set: VectorSet, verifier) -> None:
    artifact = vector_set.construct("P-02")
    assert artifact.paired_raw is not None
    folded = artifact.paired_raw.replace("\r\nHost: ", "\r\nHost:\r\n ", 1)
    judgment = verifier.verify(artifact.message_raw, 1795000060, paired_request_raw=folded)
    assert judgment.failing_stage == "CONTEXT"
    assert judgment.failing_code == "E_CONTEXT_PAIRED_MALFORMED"


def test_d3_ordinary_whitespace_still_parses() -> None:
    message = parse_message("GET / HTTP/1.1\r\nHost:   a  \r\nX-A:\tv\t\r\n\r\n")
    assert message.header("host") == "a"
    assert message.header("x-a") == "v"


# -- D-4 ---------------------------------------------------------------------
@pytest.mark.parametrize("value", ["caf\u00e9", "\u2603", "a\udcff"])
def test_d4_non_ascii_base_rejected(value: str) -> None:
    req = parse_message(REQUEST)
    req.set_header("x-n", value)
    with pytest.raises(ComponentError) as info:
        build_signature_base(req, _member(_item("x-n")), None)
    assert info.value.code == E_BASE_NON_ASCII


def test_d4_non_ascii_in_signature_params_rejected() -> None:
    req = parse_message(REQUEST)
    member = SFInnerList(items=[_item("@method")], params={"nonce": SFString("n\u00f8nce")})
    with pytest.raises(ComponentError) as info:
        build_signature_base(req, member, None)
    assert info.value.code == E_BASE_NON_ASCII


# -- D-5 ---------------------------------------------------------------------
def test_d5_default_port_table_and_profile_default() -> None:
    assert DEFAULT_PORTS == {"https": 443, "http": 80}
    assert PROFILE_DEFAULT_SCHEME == "https"


@pytest.mark.parametrize(
    ("host", "scheme", "expected"),
    [
        ("Svc.Example:443", "https", "svc.example"),
        ("svc.example:80", "https", "svc.example:80"),
        ("svc.example:80", "http", "svc.example"),
        ("svc.example:443", "http", "svc.example:443"),
        ("svc.example:8443", "https", "svc.example:8443"),
        ("svc.example:443", "HTTPS", "svc.example"),
        ("[2001:DB8::1]:443", "https", "[2001:db8::1]"),
        ("[2001:db8::1]:80", "http", "[2001:db8::1]"),
        ("svc.example:443", "wss", "svc.example:443"),  # no default-port entry
    ],
)
def test_d5_authority_default_port_by_scheme(host: str, scheme: str, expected: str) -> None:
    assert _authority_value(host, scheme) == expected


def test_d5_scheme_level_2_profile_default_https() -> None:
    """No explicit scheme on the artifact: the profile default https."""
    req = parse_message("GET /x HTTP/1.1\r\nHost: svc.example:443\r\n\r\n")
    assert artifact_scheme(req) is None
    assert resolve_scheme(req) == "https"
    assert derived_value("@authority", req) == "svc.example"
    port80 = parse_message("GET /x HTTP/1.1\r\nHost: svc.example:80\r\n\r\n")
    assert derived_value("@authority", port80) == "svc.example:80"


def test_d5_scheme_level_1_explicit_artifact_scheme_wins() -> None:
    """An absolute-form target carries the artifact's own scheme, and it
    wins over the profile default."""
    req = parse_message("GET HTTP://Svc.Example:80/x?q=1 HTTP/1.1\r\nHost: svc.example:80\r\n\r\n")
    assert artifact_scheme(req) == "http"
    assert resolve_scheme(req) == "http"
    assert derived_value("@authority", req) == "svc.example"
    assert derived_value("@path", req) == "/x"
    assert derived_value("@query", req) == "?q=1"
    https = parse_message("GET https://svc.example:80/ HTTP/1.1\r\nHost: svc.example:80\r\n\r\n")
    assert derived_value("@authority", https) == "svc.example:80"


def test_d5_connect_keeps_profile_default() -> None:
    """CONNECT targets are authority-form (no scheme): profile default
    https applies, so :443 is omitted (draft -09 section 3, #419)."""
    req = parse_message("CONNECT svc.example:443 HTTP/1.1\r\nHost: svc.example:443\r\n\r\n")
    assert artifact_scheme(req) is None
    assert derived_value("@authority", req) == "svc.example"


def test_d5_response_authority_needs_req() -> None:
    resp = parse_message("HTTP/1.1 200 OK\r\nHost: svc.example\r\n\r\n")
    with pytest.raises(ComponentError):
        derived_value("@authority", resp)
