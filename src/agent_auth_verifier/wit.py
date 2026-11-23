"""Workload Identity Token (WIT) validation.

Implements the recipient-side WIT checks the HTTP signature profile relies
on (draft-ietf-wimse-http-signature-09 section 3, referencing the WIT
validation procedure of the workload credentials specification): the token
is a JWS signed by the issuer; the recipient verifies it against its
configured issuer trust anchor BEFORE verifying the HTTP message signature,
checks its validity window at the verification time, and extracts the
cnf.jwk key binding that section 3.1 makes authoritative for the message
signature algorithm and key.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from .crypto import b64u_decode, jwk_to_public_key, verify_signature


class WitError(ValueError):
    """WIT validation failure; .code is the failure classification."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


@dataclass
class WitInfo:
    header: dict
    claims: dict
    cnf_jwk: dict

    @property
    def alg(self) -> str:
        return str(self.cnf_jwk.get("alg", ""))

    @property
    def kid(self) -> str | None:
        kid = self.cnf_jwk.get("kid")
        return str(kid) if kid is not None else None

    @property
    def subject(self) -> str | None:
        sub = self.claims.get("sub")
        return str(sub) if sub is not None else None


def _decode_json_segment(segment: str, what: str) -> dict:
    try:
        value = json.loads(b64u_decode(segment))
    except Exception as exc:
        raise WitError("E_WIT_MALFORMED", f"WIT {what} is not valid base64url JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise WitError("E_WIT_MALFORMED", f"WIT {what} is not a JSON object")
    return value


def validate_wit(token: str, issuer_anchor_jwk: dict, verify_time: int) -> WitInfo:
    """Validate a WIT JWS against the issuer trust anchor at verify_time.

    Raises WitError with one of: E_WIT_MALFORMED, E_WIT_SIGNATURE,
    E_WIT_EXPIRED, E_WIT_NOT_YET_VALID, E_WIT_CNF_MISSING.
    """
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise WitError("E_WIT_MALFORMED", "WIT is not a three-part JWS")
    header = _decode_json_segment(parts[0], "header")
    claims = _decode_json_segment(parts[1], "claims")
    try:
        signature = b64u_decode(parts[2])
    except Exception as exc:
        raise WitError("E_WIT_MALFORMED", f"WIT signature is not base64url: {exc}") from exc
    anchor_alg = str(issuer_anchor_jwk.get("alg", ""))
    header_alg = str(header.get("alg", ""))
    if header_alg != anchor_alg:
        raise WitError(
            "E_WIT_SIGNATURE",
            f"WIT header alg {header_alg!r} does not match issuer anchor alg {anchor_alg!r}",
        )
    anchor_key = jwk_to_public_key(issuer_anchor_jwk)
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    if not verify_signature(anchor_alg, anchor_key, signature, signing_input):
        raise WitError("E_WIT_SIGNATURE", "WIT signature does not verify under the issuer anchor")
    exp = claims.get("exp")
    if not isinstance(exp, int):
        raise WitError("E_WIT_MALFORMED", "WIT has no integer exp claim")
    if verify_time >= exp:
        raise WitError("E_WIT_EXPIRED", f"WIT expired at {exp}, verification time {verify_time}")
    iat = claims.get("iat")
    if isinstance(iat, int) and verify_time < iat:
        raise WitError(
            "E_WIT_NOT_YET_VALID", f"WIT iat {iat} is after verification time {verify_time}"
        )
    cnf = claims.get("cnf")
    jwk = cnf.get("jwk") if isinstance(cnf, dict) else None
    if not isinstance(jwk, dict) or "alg" not in jwk:
        raise WitError("E_WIT_CNF_MISSING", "WIT has no cnf.jwk key binding with an alg")
    return WitInfo(header=header, claims=claims, cnf_jwk=jwk)
