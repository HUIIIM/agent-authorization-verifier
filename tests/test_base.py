"""Signature base construction (RFC 9421 section 2.5) against the bases
published with the vector set, plus the derived-component rules that the
-09 draft pins down."""

import pytest

from agent_auth_verifier.components import build_signature_base, derived_value
from agent_auth_verifier.httpmsg import parse_message
from agent_auth_verifier.sf import SFInnerList, parse_dictionary
from agent_auth_verifier.vectors import VectorSet

BASE_CASES = ["P-01", "P-02", "P-03", "P-04", "P-05", "P-06", "N-09b", "N-15"]


@pytest.mark.parametrize("vector_id", BASE_CASES)
def test_constructed_base_matches_published_base(vector_set: VectorSet, vector_id: str) -> None:
    vec = vector_set.vectors[vector_id]
    provided = vec["signature_base_provided"]
    assert provided, f"{vector_id} carries no published base"
    message = parse_message(vector_set.base_message_raw(vector_id))
    paired = None
    if vec.get("paired_request_ref"):
        paired = parse_message(vector_set.base_message_raw(vec["paired_request_ref"]))
    sig_input = parse_dictionary(message.header("signature-input") or "")
    for label, expected_base in provided.items():
        member = sig_input[label]
        assert isinstance(member, SFInnerList)
        constructed = build_signature_base(message, member, paired)
        assert constructed == expected_base, f"{vector_id}/{label}"


def test_connect_authority_omits_default_port(vector_set: VectorSet) -> None:
    """draft-ietf-wimse-http-signature-09, section 3 (change #419 relative
    to -08): the @authority value of a CONNECT request follows RFC 9421
    section 2.2.3 -- the default port is omitted even though the CONNECT
    target carries it."""
    message = parse_message(vector_set.base_message_raw("P-04"))
    assert message.target == "svcb.example.com:443"
    assert derived_value("@authority", message) == "svcb.example.com"


def test_query_component_forms(vector_set: VectorSet) -> None:
    with_query = parse_message(vector_set.base_message_raw("P-01"))
    assert derived_value("@query", with_query) == "?flavor=vanilla"
    without_query = parse_message(vector_set.base_message_raw("P-05"))
    assert derived_value("@query", without_query) == "?"


def test_status_and_req_components(vector_set: VectorSet) -> None:
    response = parse_message(vector_set.base_message_raw("P-02"))
    request = parse_message(vector_set.base_message_raw("P-01"))
    assert derived_value("@status", response) == "404"
    sig_input = parse_dictionary(response.header("signature-input") or "")
    member = sig_input["sig1"]
    assert isinstance(member, SFInnerList)
    base = build_signature_base(response, member, request)
    assert '"@method";req: GET' in base
    assert '"@query";req: ?flavor=vanilla' in base
