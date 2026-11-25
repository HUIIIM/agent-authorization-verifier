"""Workload Identity Token (WIT) pre-checks.

Implements the WIT pre-checks of the S-01 design (section 3.2, WIT row),
in the row's order:

1. JWS signature verification against the Issuer trust anchor (RFC 7515).
   The token must be a single well-formed JWT in JWS compact
   serialization, and the header ``alg`` must match the anchor's ``alg``.
2. The ``typ`` header must be ``wit+jwt``.
3. ``exp`` must be after the verification moment (RFC 7519 section 4.1.4).
4. ``cnf.jwk`` is the sole source of the binding key (RFC 7800 section
   3.1); the ``jwk`` object must carry an ``alg`` member.

Failures raise :class:`WitError` with one of the design row's codes:
``E_WIT_SIG``, ``E_WIT_TYPE``, ``E_WIT_EXP``, ``E_WIT_CNF``.

The fine detail follows the design row, not the draft directly; see
``docs/w3-wit-u3.md`` for the U3 alignment of the row against
``draft-ietf-wimse-workload-creds-03`` section 5.1.3 (the draft has no
section 5.1.4) and the differences registered for household decision.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .crypto import b64u_decode, jwk_to_public_key, verify_signature


class WitError(ValueError):
    """A WIT pre-check failure. ``code`` is the stable error code."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


@dataclass
class WitInfo:
    """The validated WIT: the binding key and the workload subject."""

    header: dict[str, Any]
    claims: dict[str, Any]
    cnf_jwk: dict[str, Any]

    @property
    def alg(self) -> str:
        """The binding key algorithm, from ``cnf.jwk.alg``."""
        return str(self.cnf_jwk.get("alg", ""))

    @property
    def kid(self) -> str | None:
        """The binding key id, from ``cnf.jwk.kid`` (absent in some vectors)."""
        kid = self.cnf_jwk.get("kid")
        return str(kid) if kid is not None else None

    @property
    def subject(self) -> str | None:
        """The workload subject, from the ``sub`` claim."""
        sub = self.claims.get("sub")
        return str(sub) if sub is not None else None


@dataclass
class WitStep:
    """One WIT sub-step of the section 2.2 stepwise contrast table."""

    step: str  # "1" | "1b" | "1c"
    label: str
    status: str  # "pass" | "fail" | "skip"
    code: str | None
    detail: str


def _decode_json_segment(segment: str, what: str) -> dict[str, Any]:
    """Decode one base64url JSON segment, or raise E_WIT_SIG."""
    try:
        value = json.loads(b64u_decode(segment))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WitError("E_WIT_SIG", f"{what} is not base64url JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise WitError("E_WIT_SIG", f"{what} is not a JSON object")
    return value


def _parse(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    """Split a JWS compact serialization; E_WIT_SIG on any structural problem."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise WitError("E_WIT_SIG", "JWS compact serialization needs 3 parts")
    header = _decode_json_segment(parts[0], "JWS header")
    claims = _decode_json_segment(parts[1], "JWS claims")
    try:
        signature = b64u_decode(parts[2])
    except ValueError as exc:
        raise WitError("E_WIT_SIG", f"bad signature encoding: {exc}") from exc
    try:
        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    except UnicodeEncodeError as exc:
        raise WitError("E_WIT_SIG", "JWS header/claims are not ASCII") from exc
    return header, claims, signature, signing_input


def _check_signature(
    header: dict[str, Any],
    issuer_anchor_jwk: dict[str, Any],
    signature: bytes,
    signing_input: bytes,
) -> None:
    """Verify the JWS signature under the issuer anchor, or raise E_WIT_SIG."""
    anchor_alg = str(issuer_anchor_jwk.get("alg", ""))
    header_alg = str(header.get("alg", ""))
    if header_alg != anchor_alg:
        raise WitError(
            "E_WIT_SIG",
            f"WIT header alg {header_alg!r} does not match issuer anchor alg {anchor_alg!r}",
        )
    anchor_key = jwk_to_public_key(issuer_anchor_jwk)
    if not verify_signature(header_alg, anchor_key, signature, signing_input):
        raise WitError("E_WIT_SIG", "JWS signature invalid under the issuer anchor")


def _check_typ(header: dict[str, Any]) -> None:
    """Require the typ header to be wit+jwt, or raise E_WIT_TYPE."""
    if header.get("typ") != "wit+jwt":
        raise WitError("E_WIT_TYPE", f"WIT typ {header.get('typ')!r} is not 'wit+jwt'")


def _check_exp(claims: dict[str, Any], verify_time: int) -> None:
    """Require an integer exp after verify_time, or raise E_WIT_EXP."""
    exp = claims.get("exp")
    if not isinstance(exp, int) or isinstance(exp, bool):
        raise WitError("E_WIT_EXP", "WIT has no integer exp claim")
    if verify_time >= exp:
        raise WitError(
            "E_WIT_EXP", f"WIT expired: exp {exp} is not after verify_time {verify_time}"
        )


def _extract_cnf(claims: dict[str, Any]) -> dict[str, Any]:
    """Return cnf.jwk, or raise E_WIT_CNF."""
    cnf = claims.get("cnf")
    jwk = cnf.get("jwk") if isinstance(cnf, dict) else None
    if not isinstance(jwk, dict) or "alg" not in jwk:
        raise WitError("E_WIT_CNF", "WIT has no cnf.jwk key binding with an alg")
    return jwk


def validate_wit(token: str, issuer_anchor_jwk: dict[str, Any], verify_time: int) -> WitInfo:
    """Validate a WIT (JWS compact serialization) against an issuer anchor.

    Steps, in design order: JWS signature under the issuer anchor, ``typ``,
    ``exp`` after ``verify_time``, ``cnf.jwk`` as the binding key.

    Raises WitError with one of: E_WIT_SIG, E_WIT_TYPE, E_WIT_EXP, E_WIT_CNF.
    """
    header, claims, signature, signing_input = _parse(token)
    _check_signature(header, issuer_anchor_jwk, signature, signing_input)
    _check_typ(header)
    _check_exp(claims, verify_time)
    cnf_jwk = _extract_cnf(claims)
    return WitInfo(header=header, claims=claims, cnf_jwk=cnf_jwk)


def wit_steps(token: str, issuer_anchor_jwk: dict[str, Any], verify_time: int) -> list[WitStep]:
    """Evaluate the WIT sub-steps of the section 2.2 stepwise table.

    Each sub-step is evaluated on its own merits, so the table shows every
    sub-step's own status even when an earlier check fails:

    * ``1`` -- issuer signature: the token is a well-formed JWS, the header
      ``alg`` matches the issuer anchor, the signature verifies under the
      anchor, and ``typ`` is ``wit+jwt`` (E_WIT_SIG / E_WIT_TYPE).
    * ``1b`` -- cnf binding: ``cnf.jwk`` is present with an ``alg`` member
      (E_WIT_CNF).
    * ``1c`` -- WIT not expired: integer ``exp`` after ``verify_time``
      (E_WIT_EXP).

    A sub-step that cannot be evaluated (the token does not parse) is
    ``skip``.
    """
    try:
        header, claims, signature, signing_input = _parse(token)
    except WitError as exc:
        return [
            WitStep(
                step="1",
                label="WIT issuer signature",
                status="fail",
                code=exc.code,
                detail=exc.detail,
            ),
            WitStep(
                step="1b",
                label="WIT cnf binding",
                status="skip",
                code=None,
                detail="token does not parse",
            ),
            WitStep(
                step="1c",
                label="WIT not expired",
                status="skip",
                code=None,
                detail="token does not parse",
            ),
        ]
    try:
        _check_signature(header, issuer_anchor_jwk, signature, signing_input)
        _check_typ(header)
    except WitError as exc:
        step1 = WitStep(
            step="1",
            label="WIT issuer signature",
            status="fail",
            code=exc.code,
            detail=exc.detail,
        )
    else:
        step1 = WitStep(
            step="1",
            label="WIT issuer signature",
            status="pass",
            code=None,
            detail="signature valid under the issuer anchor; typ wit+jwt",
        )
    try:
        _extract_cnf(claims)
    except WitError as exc:
        step1b = WitStep(
            step="1b",
            label="WIT cnf binding",
            status="fail",
            code=exc.code,
            detail=exc.detail,
        )
    else:
        step1b = WitStep(
            step="1b",
            label="WIT cnf binding",
            status="pass",
            code=None,
            detail="cnf.jwk present with an alg member",
        )
    try:
        _check_exp(claims, verify_time)
    except WitError as exc:
        step1c = WitStep(
            step="1c",
            label="WIT not expired",
            status="fail",
            code=exc.code,
            detail=exc.detail,
        )
    else:
        step1c = WitStep(
            step="1c",
            label="WIT not expired",
            status="pass",
            code=None,
            detail="exp is after the verification moment",
        )
    return [step1, step1b, step1c]
