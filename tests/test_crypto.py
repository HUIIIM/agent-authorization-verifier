"""Cryptographic primitives: JWK handling, Ed25519/ES256 verification,
WIT validation, and the suite's deterministic key derivation (an
independent recomputation of the published test materials)."""

import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from agent_auth_verifier.crypto import (
    b64u_decode,
    b64u_encode,
    jwk_to_public_key,
    verify_signature,
)
from agent_auth_verifier.vectors import VectorSet
from agent_auth_verifier.wit import WitError, validate_wit

T0 = 1795000000


def _key(vector_set: VectorSet, name: str) -> dict:
    for key in vector_set.materials["keys"]:
        if key["name"] == name:
            return key
    raise KeyError(name)


def test_ed25519_key_derivation_matches_published_jwk(vector_set: VectorSet) -> None:
    for name in ("issuer", "svcA", "svcB", "other"):
        key = _key(vector_set, name)
        seed = hashlib.sha256(f"s01-validation-vectors:{name}".encode()).digest()
        assert b64u_encode(seed) == key["private_d"]
        private = Ed25519PrivateKey.from_private_bytes(seed)
        public_raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        assert b64u_encode(public_raw) == key["public_jwk"]["x"]


# The P-256 group order (FIPS 186-4), a public constant of the curve.
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def test_es256_key_derivation_matches_published_jwk(vector_set: VectorSet) -> None:
    key = _key(vector_set, "svcC")
    scalar = (
        int.from_bytes(hashlib.sha256(b"s01-validation-vectors:svcC").digest(), "big")
        % (P256_ORDER - 1)
        + 1
    )
    assert b64u_encode(scalar.to_bytes(32, "big")) == key["private_d"]


def test_ed25519_verify_and_tamper(vector_set: VectorSet) -> None:
    key = _key(vector_set, "svcA")
    public = jwk_to_public_key(key["public_jwk"])
    data = b"test data"
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private = Ed25519PrivateKey.from_private_bytes(b64u_decode(key["private_d"]))
    signature = private.sign(data)
    assert verify_signature("Ed25519", public, signature, data)
    assert not verify_signature("Ed25519", public, signature, data + b"x")
    assert not verify_signature("Ed25519", public, signature[:-1] + b"\x00", data)


def test_wit_validation_happy_path(vector_set: VectorSet) -> None:
    anchor = vector_set.materials["trusted_config"]["issuer_anchor_jwk"]
    info = validate_wit(vector_set.materials["wits"]["WIT-A"]["jws"], anchor, T0 + 60)
    assert info.subject == "wimse://example.com/svcA"
    assert info.alg == "Ed25519"
    assert info.kid == "vec-a-key"


def test_wit_expired_at_exp_instant(vector_set: VectorSet) -> None:
    """WIT-A expires at T0+3600; at that instant the token is no longer
    valid (a JWT MUST NOT be accepted at or after its exp)."""
    anchor = vector_set.materials["trusted_config"]["issuer_anchor_jwk"]
    with pytest.raises(WitError) as excinfo:
        validate_wit(vector_set.materials["wits"]["WIT-A"]["jws"], anchor, T0 + 3600)
    assert excinfo.value.code == "E_WIT_EXP"


def test_wit_signature_tamper(vector_set: VectorSet) -> None:
    anchor = vector_set.materials["trusted_config"]["issuer_anchor_jwk"]
    token = vector_set.materials["wits"]["WIT-B"]["jws"]
    head, payload, signature = token.split(".")
    raw = bytearray(b64u_decode(signature))
    raw[0] ^= 0x01
    tampered = f"{head}.{payload}.{b64u_encode(bytes(raw))}"
    with pytest.raises(WitError) as excinfo:
        validate_wit(tampered, anchor, T0 + 60)
    assert excinfo.value.code == "E_WIT_SIG"
