"""JWK handling and signature primitives for the two algorithms the WIMSE
profile binds through the WIT cnf claim: Ed25519 and ES256 (ECDSA over
P-256 with SHA-256, JWS raw r||s signature encoding).

Signing is included for test-vector regeneration (the suite's A-04 rule);
the verifier itself only verifies. No network access anywhere in this
module.
"""

from __future__ import annotations

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    EllipticCurvePrivateNumbers,
    EllipticCurvePublicNumbers,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.hashes import SHA256

PublicKeyTypes = (Ed25519PublicKey, ec.EllipticCurvePublicKey)
PrivateKeyTypes = (Ed25519PrivateKey, ec.EllipticCurvePrivateKey)


def b64u_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def jwk_to_public_key(jwk: dict) -> Ed25519PublicKey | ec.EllipticCurvePublicKey:
    kty = jwk.get("kty")
    if kty == "OKP" and jwk.get("crv") == "Ed25519":
        return Ed25519PublicKey.from_public_bytes(b64u_decode(jwk["x"]))
    if kty == "EC" and jwk.get("crv") == "P-256":
        numbers = EllipticCurvePublicNumbers(
            x=int.from_bytes(b64u_decode(jwk["x"]), "big"),
            y=int.from_bytes(b64u_decode(jwk["y"]), "big"),
            curve=SECP256R1(),
        )
        return numbers.public_key()
    raise ValueError(f"unsupported JWK: kty={kty!r} crv={jwk.get('crv')!r}")


def jwk_to_private_key(jwk: dict) -> Ed25519PrivateKey | ec.EllipticCurvePrivateKey:
    kty = jwk.get("kty")
    if kty == "OKP" and jwk.get("crv") == "Ed25519":
        return Ed25519PrivateKey.from_private_bytes(b64u_decode(jwk["d"]))
    if kty == "EC" and jwk.get("crv") == "P-256":
        public = jwk_to_public_key(jwk)
        assert isinstance(public, ec.EllipticCurvePublicKey)
        numbers = EllipticCurvePrivateNumbers(
            private_value=int.from_bytes(b64u_decode(jwk["d"]), "big"),
            public_numbers=public.public_numbers(),
        )
        return numbers.private_key()
    raise ValueError(f"unsupported JWK: kty={kty!r} crv={jwk.get('crv')!r}")


def verify_signature(alg: str, public_key: object, signature: bytes, data: bytes) -> bool:
    """Verify a signature under the algorithm named by the WIT cnf.jwk alg
    value (draft section 3.1). ES256 signatures use the JWS raw r||s
    encoding. Returns False on any verification failure."""
    try:
        if alg == "Ed25519":
            if not isinstance(public_key, Ed25519PublicKey):
                return False
            public_key.verify(signature, data)
            return True
        if alg == "ES256":
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                return False
            if len(signature) != 64:
                return False
            r = int.from_bytes(signature[:32], "big")
            s = int.from_bytes(signature[32:], "big")
            der = encode_dss_signature(r, s)
            public_key.verify(der, data, ec.ECDSA(SHA256()))
            return True
    except (InvalidSignature, ValueError, TypeError):
        # Any failure to verify -- bad signature, malformed signature
        # bytes, wrong key type -- means the signature does not verify.
        return False
    return False


def sign(alg: str, private_key: object, data: bytes) -> bytes:
    """Sign data; ES256 output is converted to the JWS raw r||s encoding.
    Used only by the vector regeneration path (suite rule A-04). Ed25519 is
    deterministic by construction; ES256 output here is a valid signature
    but not byte-reproducible (the library does not implement RFC 6979)."""
    if alg == "Ed25519":
        assert isinstance(private_key, Ed25519PrivateKey)
        return private_key.sign(data)
    if alg == "ES256":
        assert isinstance(private_key, ec.EllipticCurvePrivateKey)
        der = private_key.sign(data, ec.ECDSA(SHA256()))
        r, s = decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")
    raise ValueError(f"unsupported alg {alg!r}")
