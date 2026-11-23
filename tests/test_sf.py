"""RFC 8941 structured-field parsing/serialization round trips."""

import pytest

from agent_auth_verifier.sf import (
    SFBytes,
    SFInnerList,
    SFItem,
    SFParseError,
    SFString,
    parse_dictionary,
    serialize_dictionary,
)

SIGNATURE_INPUT = (
    'sig1=("@method" "@path" "@query" "workload-identity-token")'
    ";created=1795000000;expires=1795000300"
    ';nonce="7f3a9c1e5b284d06a1f4e8c2b6d50937"'
    ';tag="wimse-workload-to-workload"'
    ';wimse-aud="https://svcb.example.com/gimme-ice-cream"'
    ";wimse-sign-response"
)


def test_signature_input_round_trip() -> None:
    members = parse_dictionary(SIGNATURE_INPUT)
    assert serialize_dictionary(members) == SIGNATURE_INPUT


def test_member_structure() -> None:
    members = parse_dictionary(SIGNATURE_INPUT)
    member = members["sig1"]
    assert isinstance(member, SFInnerList)
    assert [item.value for item in member.items] == [
        SFString("@method"),
        SFString("@path"),
        SFString("@query"),
        SFString("workload-identity-token"),
    ]
    assert member.params["created"] == 1795000000
    assert member.params["wimse-sign-response"] is True
    assert member.params["tag"] == SFString("wimse-workload-to-workload")


def test_req_parameter_round_trip() -> None:
    text = 'sig1=("@status" "@method";req "@path";req)'
    members = parse_dictionary(text)
    assert serialize_dictionary(members) == text
    member = members["sig1"]
    assert isinstance(member, SFInnerList)
    assert member.items[1].params == {"req": True}


def test_signature_dictionary_byte_sequence() -> None:
    # P-01's published Ed25519 signature value (64 bytes).
    text = (
        "sig1=:qrIGE6wS80/UvhJx96iDiz90OIYmUX8CFO4vOeK/40D7pnukeikqvsYGDs6aqXx0"
        "99ILxgZliEepCw1P5M7YDg==:"
    )
    members = parse_dictionary(text)
    member = members["sig1"]
    assert isinstance(member, SFItem)
    assert isinstance(member.value, SFBytes)
    assert len(member.value.value) == 64
    assert serialize_dictionary(members) == text


def test_two_member_dictionary() -> None:
    text = 'sig1=("@method");created=1, sig2=("@method" "@path");created=2;keyid="other-key"'
    members = parse_dictionary(text)
    assert list(members) == ["sig1", "sig2"]
    assert serialize_dictionary(members) == text


def test_boolean_and_decimal() -> None:
    members = parse_dictionary("a=?1, b=1.5, c=-42")
    assert members["a"] == SFItem(value=True)
    assert members["b"] == SFItem(value="1.5")
    assert members["c"] == SFItem(value=-42)
    assert serialize_dictionary(members) == "a=?1, b=1.5, c=-42"


@pytest.mark.parametrize(
    "bad",
    [
        'sig1=("@method"',  # unterminated inner list
        'sig1="@unterminated',  # unterminated string
        "sig1=:not base64!:",  # invalid byte sequence
        "sig1=1, sig1=2",  # duplicate key
        "sig1=1,",  # trailing comma
    ],
)
def test_parse_errors(bad: str) -> None:
    with pytest.raises(SFParseError):
        parse_dictionary(bad)
