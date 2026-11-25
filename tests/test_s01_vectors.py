"""S-01 vectors: RFC 9421 positive oracles and the gap negatives.

Every vector below carries its exact source section in VECTORS (and the
RFC 9421 fixtures carry theirs in tests/fixtures/rfc9421/manifest.json).

Positive vectors -- independent oracles taken verbatim from RFC 9421:

* V-P1   RFC 9421 Section 2.5, Figure 1 (example signature base) over the
         Section 2.5 example request.
* V-P2.n RFC 9421 Appendix B.2.n, n = 1..6, each its own oracle over the
         Appendix B.2 test-request / test-response. Errata supplement Q-3:
         RFC 9421 has 2 reported errata (EID 8102, EID 8103, Section 7.2.8 /
         Section 7.5.3 terminology only), 0 in Section 2.5 and 0 in
         Appendix B, so the paused-oracle list is empty and no B.2 example
         is excluded. B.2.2 covers "@query-param";name="Pet", which is
         outside the WIMSE component subset; its oracle is that the base is
         refused with a hard ComponentError rather than built wrong.

Negative vectors -- one per gap, built from suite vector P-01:

* V-N1 (D-1) RFC 9421 Section 2.5, step 2.1: a duplicated component
       identifier.
* V-N2 (D-2) RFC 9421 Section 2.5, step 2.5 (third bullet): ;req on a
       request.
* V-N3 (D-3) RFC 9112 Section 5.2 (obs-fold), with RFC 9421 Section 2.5
       ABNF ("no obs-fold nor obs-text"): a folded field line.
* V-N4 (D-4) RFC 9421 Section 2.5, step 4: a non-ASCII signature base.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from agent_auth_verifier.components import (
    ComponentError,
    build_signature_base,
)
from agent_auth_verifier.crypto import jwk_to_public_key, verify_signature
from agent_auth_verifier.httpmsg import HttpMessage, parse_message
from agent_auth_verifier.sf import (
    SFBytes,
    SFInnerList,
    SFItem,
    SFString,
    parse_dictionary,
    serialize_dictionary,
    serialize_member,
)
from agent_auth_verifier.vectors import VectorSet

RFC_DIR = Path(__file__).parent / "fixtures" / "rfc9421"

VECTORS: dict[str, str] = {
    "V-P1": "RFC 9421 Section 2.5, Figure 1",
    "V-P2.1": "RFC 9421 Appendix B.2.1",
    "V-P2.2": "RFC 9421 Appendix B.2.2",
    "V-P2.3": "RFC 9421 Appendix B.2.3",
    "V-P2.4": "RFC 9421 Appendix B.2.4",
    "V-P2.5": "RFC 9421 Appendix B.2.5",
    "V-P2.6": "RFC 9421 Appendix B.2.6",
    "V-N1": "RFC 9421 Section 2.5, step 2.1 (D-1)",
    "V-N2": "RFC 9421 Section 2.5, step 2.5, third bullet (D-2)",
    "V-N3": "RFC 9112 Section 5.2; RFC 9421 Section 2.5 ABNF (D-3)",
    "V-N4": "RFC 9421 Section 2.5, step 4 (D-4)",
}

VERIFY_TIME = 1795000060  # inside P-01's signature window and WIT-A validity


# -- RFC 9421 fixture helpers ----------------------------------------------
def _rfc(name: str) -> str:
    return (RFC_DIR / name).read_text()


def unwrap_8792(text: str) -> str:
    """Undo RFC 8792 single-backslash line wrapping (RFC 8792 Section 7.2.2):
    drop the NOTE header and its blank line, then join every line that ends
    in a backslash with the next line minus its leading whitespace."""
    lines = text.rstrip("\n").split("\n")
    if lines[0] == "NOTE: '\\' line wrapping per RFC 8792":
        assert lines[1] == ""
        lines = lines[2:]
    return re.sub(r"\\\n[ ]*", "", "\n".join(lines))


def _wire(text: str) -> str:
    """RFC example message (LF lines) to the CRLF wire form."""
    head, _, body = unwrap_8792(text).partition("\n\n")
    return head.replace("\n", "\r\n") + "\r\n\r\n" + body


def _with_fields(message: HttpMessage, fields_text: str) -> tuple[str, SFInnerList, bytes]:
    """Attach a B.2.n Signature-Input/Signature pair to a message."""
    lines = dict(line.split(": ", 1) for line in unwrap_8792(fields_text).split("\n"))
    message.set_header("signature-input", lines["Signature-Input"])
    message.set_header("signature", lines["Signature"])
    ((label, member),) = parse_dictionary(lines["Signature-Input"]).items()
    ((sig_label, sig),) = parse_dictionary(lines["Signature"]).items()
    assert label == sig_label
    assert isinstance(member, SFInnerList)
    assert isinstance(sig, SFItem) and isinstance(sig.value, SFBytes)
    return label, member, sig.value.value


def test_every_vector_has_a_source_section() -> None:
    assert set(VECTORS) == {
        "V-P1",
        *(f"V-P2.{n}" for n in range(1, 7)),
        "V-N1",
        "V-N2",
        "V-N3",
        "V-N4",
    }
    for source in VECTORS.values():
        assert re.match(r"RFC \d+ (Section|Appendix) [A-Z0-9.]+", source)
    manifest = json.loads(_rfc("manifest.json"))
    for name, entry in manifest["files"].items():
        assert (RFC_DIR / name).is_file()
        assert re.match(r"RFC 9421 (Section|Appendix) [A-Z0-9.]+", entry["source_section"])


def test_unwrap_8792_on_figure_1_digest() -> None:
    base = unwrap_8792(_rfc("s2.5-figure1-base.txt"))
    assert (
        '"content-digest": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+'
        "AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"
    ) in base.split("\n")


# -- V-P1: RFC 9421 Section 2.5, Figure 1 ----------------------------------
def test_vp1_rfc9421_section_2_5_figure_1() -> None:
    """V-P1 -- RFC 9421 Section 2.5, Figure 1: the signature base of the
    Section 2.5 example request, byte for byte. The covered components and
    parameters are those stated in the Section 2.5 prose (@method,
    @authority, @path, Content-Digest, Content-Length, Content-Type;
    created=1618884473, keyid="test-key-rsa-pss")."""
    message = parse_message(_wire(_rfc("s2.5-request.txt")))
    member = SFInnerList(
        items=[
            SFItem(value=SFString(name))
            for name in (
                "@method",
                "@authority",
                "@path",
                "content-digest",
                "content-length",
                "content-type",
            )
        ],
        params={"created": 1618884473, "keyid": SFString("test-key-rsa-pss")},
    )
    expected = unwrap_8792(_rfc("s2.5-figure1-base.txt"))
    assert build_signature_base(message, member, None) == expected


# -- V-P2: RFC 9421 Appendix B.2, every example an independent oracle ------
B2_REQUEST = {1, 2, 3, 5, 6}  # B.2.4 is over test-response
B2_PROFILE_KEYS = {
    4: ("ES256", "b1.3-test-key-ecc-p256.jwk.json"),  # ecdsa-p256-sha256
    6: ("Ed25519", "b1.4-test-key-ed25519.jwk.json"),  # ed25519
}


def _b2_message(n: int) -> HttpMessage:
    name = "b2-test-request.txt" if n in B2_REQUEST else "b2-test-response.txt"
    return parse_message(_wire(_rfc(name)))


@pytest.mark.parametrize("n", [1, 3, 4, 5, 6])
def test_vp2_rfc9421_appendix_b2_signature_base(n: int) -> None:
    """V-P2.n -- RFC 9421 Appendix B.2.n: the constructed signature base
    equals the published one, byte for byte, with the Signature-Input
    taken from the published B.2.n fields."""
    message = _b2_message(n)
    _, member, _ = _with_fields(message, _rfc(f"b2.{n}-fields.txt"))
    expected = unwrap_8792(_rfc(f"b2.{n}-base.txt"))
    assert build_signature_base(message, member, None) == expected
    # The published Signature-Input serializes back exactly as its base line.
    assert expected.endswith('"@signature-params": ' + serialize_member(member))


@pytest.mark.parametrize("n", sorted(B2_PROFILE_KEYS))
def test_vp2_rfc9421_appendix_b2_signature_verifies(n: int) -> None:
    """V-P2.4 (ecdsa-p256-sha256, Appendix B.1.3 key) and V-P2.6 (ed25519,
    Appendix B.1.4 key): the published signature verifies over the
    constructed base with the profile's ES256 / Ed25519 primitives, and
    fails over a one-byte-altered base."""
    alg, key_file = B2_PROFILE_KEYS[n]
    message = _b2_message(n)
    _, member, signature = _with_fields(message, _rfc(f"b2.{n}-fields.txt"))
    base = build_signature_base(message, member, None).encode("ascii")
    public = jwk_to_public_key(json.loads(_rfc(key_file)))
    assert verify_signature(alg, public, signature, base)
    assert not verify_signature(alg, public, signature, base + b" ")


def test_vp2_2_rfc9421_appendix_b2_2_query_param_is_out_of_scope() -> None:
    """V-P2.2 -- RFC 9421 Appendix B.2.2 covers "@query-param";name="Pet".
    That component is outside the WIMSE subset (scope rule 1), so the
    oracle here is the scope boundary: the base is refused with a hard
    ComponentError, never built without the component or with a guessed
    value. The components the subset does support still match the
    published base lines exactly."""
    message = _b2_message(2)
    _, member, _ = _with_fields(message, _rfc("b2.2-fields.txt"))
    with pytest.raises(ComponentError, match="not supported"):
        build_signature_base(message, member, None)
    expected_lines = unwrap_8792(_rfc("b2.2-base.txt")).split("\n")
    supported = SFInnerList(items=member.items[:2], params={})
    built = build_signature_base(message, supported, None).split("\n")[:2]
    assert built == expected_lines[:2]


# -- negative vectors over suite P-01 --------------------------------------
def _p01(vector_set: VectorSet) -> tuple[HttpMessage, dict, SFInnerList]:
    message = parse_message(vector_set.base_message_raw("P-01"))
    sig_input = parse_dictionary(message.header("signature-input") or "")
    member = sig_input["sig1"]
    assert isinstance(member, SFInnerList)
    return message, sig_input, member


def _resign(vector_set: VectorSet, message: HttpMessage, sig_input: dict, base: str) -> str:
    """Re-sign over the given base with the WIT-bound test key, so a vector
    fails only on its targeted defect, never merely on a stale signature."""
    signature = vector_set._sign_with_wit_key(message, base)
    message.set_header("signature-input", serialize_dictionary(sig_input))
    message.set_header(
        "signature", serialize_dictionary({"sig1": SFItem(value=SFBytes(signature))})
    )
    return message.serialize()


def _naive_base(message: HttpMessage, member: SFInnerList, extra_lines: list[str]) -> str:
    """The base a lenient implementation would produce: the valid component
    lines, the offending extra lines, then the params line."""
    original = SFInnerList(items=member.items[: len(member.items) - len(extra_lines)])
    lines = build_signature_base(message, original, None).split("\n")[:-1]
    return "\n".join(lines + extra_lines + ['"@signature-params": ' + serialize_member(member)])


def test_p01_control_accepts(vector_set: VectorSet, verifier) -> None:
    judgment = verifier.verify(vector_set.base_message_raw("P-01"), VERIFY_TIME)
    assert judgment.verdict == "ACCEPT"


def test_vn1_duplicate_component(vector_set: VectorSet, verifier) -> None:
    """V-N1 (D-1) -- RFC 9421 Section 2.5, step 2.1: "@method" covered
    twice, re-signed over the lenient base; rejected at BASE."""
    message, sig_input, member = _p01(vector_set)
    member.items.append(SFItem(value=SFString("@method")))
    raw = _resign(vector_set, message, sig_input, _naive_base(message, member, ['"@method": GET']))
    judgment = verifier.verify(raw, VERIFY_TIME)
    assert (judgment.verdict, judgment.failing_stage, judgment.failing_code) == (
        "REJECT",
        "BASE",
        "E_BASE_DUPLICATE_COMPONENT",
    )


def test_vn2_req_on_request_is_hard_error(vector_set: VectorSet, verifier) -> None:
    """V-N2 (D-2) -- RFC 9421 Section 2.5, step 2.5, third bullet: a request
    signature covering "@method";req. The artifact is re-signed over the
    *fallback* base (the ;req value silently taken from the message
    itself), so a verifier that falls back would ACCEPT it. It must be a
    hard BASE failure, with CRYPTO never reached."""
    message, sig_input, member = _p01(vector_set)
    member.items.append(SFItem(value=SFString("@method"), params={"req": True}))
    fallback = _naive_base(message, member, ['"@method";req: GET'])
    raw = _resign(vector_set, message, sig_input, fallback)
    judgment = verifier.verify(raw, VERIFY_TIME)
    assert (judgment.verdict, judgment.failing_stage, judgment.failing_code) == (
        "REJECT",
        "BASE",
        "E_BASE_REQ_MISUSE",
    )
    assert judgment.stage("CRYPTO").status == "blocked"
    assert judgment.signature_base is None


def test_vn3_obs_fold_rejected(vector_set: VectorSet, verifier) -> None:
    """V-N3 (D-3) -- RFC 9112 Section 5.2: P-01 with its Signature-Input
    field folded at an inner-list space. Unfolded it would be the valid
    P-01; it is rejected at CONTEXT instead of being unfolded or misread."""
    raw = vector_set.base_message_raw("P-01")
    folded = raw.replace('sig1=("@method" "@path"', 'sig1=("@method"\r\n "@path"', 1)
    assert folded != raw
    assert verifier.verify(folded.replace("\r\n ", " "), VERIFY_TIME).verdict == "ACCEPT"
    judgment = verifier.verify(folded, VERIFY_TIME)
    assert (judgment.verdict, judgment.failing_stage, judgment.failing_code) == (
        "REJECT",
        "CONTEXT",
        "E_CONTEXT_OBS_FOLD",
    )


def test_vn4_non_ascii_base(vector_set: VectorSet, verifier) -> None:
    """V-N4 (D-4) -- RFC 9421 Section 2.5, step 4: a covered header field
    whose value is non-ASCII, re-signed over the (UTF-8) lenient base;
    rejected at BASE by the final ASCII check."""
    message, sig_input, member = _p01(vector_set)
    message.set_header("x-flavor-note", "crème brûlée")
    member.items.append(SFItem(value=SFString("x-flavor-note")))
    lenient = _naive_base(message, member, ['"x-flavor-note": crème brûlée'])
    raw = _resign(vector_set, message, sig_input, lenient)
    judgment = verifier.verify(raw, VERIFY_TIME)
    assert (judgment.verdict, judgment.failing_stage, judgment.failing_code) == (
        "REJECT",
        "BASE",
        "E_BASE_NON_ASCII",
    )
