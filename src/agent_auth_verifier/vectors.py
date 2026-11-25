"""Test vector set loading, artifact construction, and suite execution.

The sole interface between this verifier and the WIMSE HTTP signature test
vector suite (HUIIIM/wimse-http-signature-test-vectors) is the vector set
version: this module consumes a published vectors.json (set v4, mapped to
draft-ietf-wimse-http-signature-08) and runs every judged vector through
the verifier.

Most negative vectors carry no literal message: they name a base vector
plus a mutation. Construction applies the mutation to the base artifact.
Where the suite's regeneration rule A-04 applies (signature_source ==
"regen"), the mutated message is re-signed with the published test
materials, exactly as the suite prescribes: Ed25519 signatures are
deterministic, so regeneration is byte-reproducible. Behavior probes
(negative-behavior) carry no artifact and are reported as not judgeable by
an artifact verifier -- an honest scope boundary, not a failure.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .components import build_signature_base
from .crypto import jwk_to_private_key, sign
from .httpmsg import HttpMessage, parse_message
from .sf import (
    SFBytes,
    SFInnerList,
    SFItem,
    SFMember,
    SFString,
    parse_dictionary,
    serialize_dictionary,
)
from .verifier import Judgment, KnownKey, TrustedConfig, Verifier

_WIT_PLACEHOLDER = re.compile(r"\[WIT-([A-Z])[^]]*\]")


@dataclass
class ConstructedArtifact:
    message_raw: str
    paired_raw: str | None
    evaluations: list[dict]
    expected_bases: dict[str, str] | None


@dataclass
class VectorOutcome:
    vector_id: str
    kind: str
    mode: str
    status: str  # "MATCH", "MISMATCH", or "NOT_JUDGEABLE"
    detail: str = ""
    evaluations: list[dict] = field(default_factory=list)


class VectorSet:
    def __init__(self, data: dict) -> None:
        self.data = data
        self.materials: dict = data["materials"]
        self.vectors: dict[str, dict] = {v["id"]: v for v in data["vectors"]}
        self.observations: list[dict] = data.get("observations", [])
        self._raw_cache: dict[str, str] = {}

    @classmethod
    def load(cls, path: str | Path) -> VectorSet:
        with open(path, encoding="utf-8") as handle:
            return cls(json.load(handle))

    def add_entry(self, entry: dict) -> None:
        """Register one vector entry by id, replacing any same-id entry.

        Used to load a contrast vector from the ``vectors/v4/`` directory
        into a set built from the fixture file.
        """
        self.vectors[entry["id"]] = entry

    @property
    def set_version(self) -> str:
        return str(self.data.get("set_version"))

    @property
    def draft_version(self) -> str:
        return str(self.data.get("draft_version"))

    def trusted_config(self) -> TrustedConfig:
        trusted = self.materials["trusted_config"]
        return TrustedConfig(
            trusted_audiences=list(trusted["wimse_aud_trusted"]),
            issuer_anchor_jwk=dict(trusted["issuer_anchor_jwk"]),
        )

    def known_keys(self) -> list[KnownKey]:
        return [
            KnownKey(name=k["name"], alg=k["alg"], public_jwk=dict(k["public_jwk"]))
            for k in self.materials["keys"]
        ]

    def make_verifier(self) -> Verifier:
        return Verifier(self.trusted_config(), known_keys=self.known_keys())

    # -- construction -------------------------------------------------------
    def _expand(self, raw: str) -> str:
        def replace(match: re.Match) -> str:
            return self.materials["wits"][f"WIT-{match.group(1)}"]["jws"]

        return _WIT_PLACEHOLDER.sub(replace, raw)

    def base_message_raw(self, vector_id: str) -> str:
        """The literal message of a vector that carries one (no mutations)."""
        if vector_id in self._raw_cache:
            return self._raw_cache[vector_id]
        vec = self.vectors[vector_id]
        message = vec.get("message")
        if message is None:
            raise ValueError(f"vector {vector_id} carries no literal message")
        raw = self._expand(str(message["raw"]))
        self._raw_cache[vector_id] = raw
        return raw

    def construct(self, vector_id: str) -> ConstructedArtifact:
        vec = self.vectors[vector_id]
        if vec.get("message") is not None:
            paired_raw = None
            if vec.get("paired_request_ref"):
                paired_raw = self.base_message_raw(str(vec["paired_request_ref"]))
            return ConstructedArtifact(
                message_raw=self.base_message_raw(vector_id),
                paired_raw=paired_raw,
                evaluations=list(vec.get("evaluations") or []),
                expected_bases=vec.get("signature_base_provided"),
            )
        # N-14 and N-21 are bespoke constructions (see their builders);
        # route by id, not by mutation op: N-21's recorded op is
        # add-component, but its base is a CONNECT migration, not P-02
        # itself, so the generic mutation path must not handle it.
        if vector_id == "N-14":
            return self._construct_n14(vec)
        if vector_id == "N-21":
            return self._construct_n21(vec)
        base_ref = str(vec["base_ref"])
        base_raw = self.base_message_raw(base_ref)
        message = parse_message(base_raw)
        paired_raw = None
        base_vec = self.vectors[base_ref]
        paired_ref = vec.get("paired_request_ref") or base_vec.get("paired_request_ref")
        if paired_ref:
            paired_raw = self.base_message_raw(str(paired_ref))
        self._apply_mutation(message, vec, paired_raw)
        return ConstructedArtifact(
            message_raw=message.serialize(),
            paired_raw=paired_raw,
            evaluations=list(vec.get("evaluations") or []),
            expected_bases=None,
        )

    def _construct_n14(self, vec: dict) -> ConstructedArtifact:
        """N-14: P-02's status line and body with all signature headers
        removed; the paired request is P-01, which required a signed
        response."""
        message = parse_message(self.base_message_raw("P-02"))
        message.remove_header("signature")
        message.remove_header("signature-input")
        return ConstructedArtifact(
            message_raw=message.serialize(),
            paired_raw=self.base_message_raw("P-01"),
            evaluations=list(vec.get("evaluations") or []),
            expected_bases=None,
        )

    def _construct_n21(self, vec: dict) -> ConstructedArtifact:
        """N-21: a P-02-shaped signed response migrated to a CONNECT
        exchange (paired request P-04), with "@path";req added to the
        coverage -- the mutation under test. Re-signed per rule A-04."""
        p02 = parse_message(self.base_message_raw("P-02"))
        p04_raw = self.base_message_raw("P-04")
        p04 = parse_message(p04_raw)
        p04_params = _wimse_member(p04).params
        p02_params = _wimse_member(p02).params
        message = HttpMessage(
            kind="response",
            status_code=p02.status_code,
            reason=p02.reason,
            version=p02.version,
            headers=[
                ("content-type", p02.header("content-type") or ""),
                ("content-digest", p02.header("content-digest") or ""),
                ("workload-identity-token", p02.header("workload-identity-token") or ""),
            ],
            body=p02.body,
        )
        components = [
            SFItem(value=SFString("@status")),
            SFItem(value=SFString("workload-identity-token")),
            SFItem(value=SFString("content-type")),
            SFItem(value=SFString("content-digest")),
            SFItem(value=SFString("@method"), params={"req": True}),
            SFItem(value=SFString("@authority"), params={"req": True}),
            SFItem(value=SFString("@path"), params={"req": True}),
        ]
        params = dict(p02_params)
        params["wimse-req-nonce"] = p04_params["nonce"]
        member = SFInnerList(items=components, params=params)
        base = build_signature_base(message, member, p04, sender_mode=True)
        signature = self._sign_with_wit_key(message, base)
        message.set_header("signature-input", serialize_dictionary({"sig1": member}))
        message.set_header(
            "signature", serialize_dictionary({"sig1": SFItem(value=SFBytes(signature))})
        )
        return ConstructedArtifact(
            message_raw=message.serialize(),
            paired_raw=p04_raw,
            evaluations=list(vec.get("evaluations") or []),
            expected_bases=None,
        )

    # -- mutation machinery ---------------------------------------------------
    def _apply_mutation(self, message: HttpMessage, vec: dict, paired_raw: str | None) -> None:
        mutation = vec.get("mutation") or {}
        op = mutation.get("op")
        if op in (None, "set-verify-time", "custom-construct"):
            return
        sig_input = parse_dictionary(message.header("signature-input") or "")
        sig_values = parse_dictionary(message.header("signature") or "")
        if op == "remove-component":
            target = _component_target(str(mutation["component"]))
            for member in sig_input.values():
                if isinstance(member, SFInnerList):
                    member.items = [
                        item for item in member.items if not _item_matches(item, target)
                    ]
            if target[0] == "content-digest":
                message.remove_header("content-digest")
        elif op == "add-component":
            item = _parse_component(str(mutation["component"]))
            member = _wimse_member_from(sig_input)
            member.items.append(item)
        elif op == "set-body":
            message.body = str(mutation["body"]).encode("utf-8")
        elif op == "remove-param":
            member = _target_member(sig_input, mutation)
            member.params.pop(str(mutation["param"]), None)
        elif op in ("add-param", "set-param"):
            member = _target_member(sig_input, mutation)
            name, value = _parse_param_assignment(str(mutation["param"]))
            member.params[name] = value
        else:
            raise ValueError(f"unsupported mutation op {op!r} in {vec['id']}")
        message.set_header("signature-input", serialize_dictionary(sig_input))
        if vec.get("signature_source") == "regen":
            paired = parse_message(paired_raw) if paired_raw else None
            for label, member in sig_input.items():
                if not isinstance(member, SFInnerList):
                    continue
                base = build_signature_base(message, member, paired, sender_mode=True)
                signature = self._sign_member(message, member, base)
                sig_values[label] = SFItem(value=SFBytes(signature))
        message.set_header("signature", serialize_dictionary(sig_values))

    def _sign_member(self, message: HttpMessage, member: SFInnerList, base: str) -> bytes:
        keyid = member.params.get("keyid")
        if isinstance(keyid, SFString):
            return self._sign_with_key_id(keyid.value, base)
        return self._sign_with_wit_key(message, base)

    def _sign_with_wit_key(self, message: HttpMessage, base: str) -> bytes:
        token = message.header("workload-identity-token") or ""
        payload = token.split(".")[1]
        from .crypto import b64u_decode

        claims = json.loads(b64u_decode(payload))
        kid = claims["cnf"]["jwk"]["kid"]
        return self._sign_with_key_id(str(kid), base)

    def _sign_with_key_id(self, kid: str, base: str) -> bytes:
        for key in self.materials["keys"]:
            if key["kid"] == kid:
                private_jwk = dict(key["public_jwk"])
                private_jwk["d"] = key["private_d"]
                private_key = jwk_to_private_key(private_jwk)
                return sign(str(key["alg"]), private_key, base.encode("utf-8"))
        raise ValueError(f"no test key with kid {kid!r}")


def _component_target(text: str) -> tuple[str, bool]:
    """Extract (component name, is_req) from a mutation component string
    such as '"@query"', '"@path";req', or 'content-digest (header and
    component)'."""
    if '"' in text:
        name = text.split('"')[1]
    else:
        name = text.split("(")[0].strip()
    return name, ";req" in text


def _item_matches(item: SFItem, target: tuple[str, bool]) -> bool:
    name, req = target
    if not isinstance(item.value, SFString):
        return False
    return item.value.value == name and (item.params.get("req") is True) == req


def _parse_component(text: str) -> SFItem:
    """Parse a mutation component string. The set writes these two ways --
    SF form ('"@path";req') and bare form ('@path') -- so normalize the
    bare form to SF form first."""
    text = text.strip()
    if not text.startswith('"'):
        if ";" in text:
            name, rest = text.split(";", 1)
            text = f'"{name.strip()}";{rest}'
        else:
            text = f'"{text}"'
    members = parse_dictionary(f"x=({text})")
    member = members["x"]
    assert isinstance(member, SFInnerList)
    return member.items[0]


def _parse_param_assignment(text: str) -> tuple[str, object]:
    members = parse_dictionary(f"k;{text}")
    member = members["k"]
    assert isinstance(member, SFItem)
    ((name, value),) = member.params.items()
    return name, value


def _wimse_member(message: HttpMessage) -> SFInnerList:
    sig_input = parse_dictionary(message.header("signature-input") or "")
    return _wimse_member_from(sig_input)


def _wimse_member_from(sig_input: dict[str, SFMember]) -> SFInnerList:
    for member in sig_input.values():
        if isinstance(member, SFInnerList):
            tag = member.params.get("tag")
            if isinstance(tag, SFString) and tag.value == "wimse-workload-to-workload":
                return member
    raise ValueError("no WIMSE-tagged signature member")


def _target_member(sig_input: dict[str, SFMember], mutation: dict) -> SFInnerList:
    label = mutation.get("member")
    if label is not None:
        member = sig_input[str(label)]
        assert isinstance(member, SFInnerList)
        return member
    return _wimse_member_from(sig_input)


# -- suite execution ----------------------------------------------------------


def run_vector_set(vector_set: VectorSet) -> list[VectorOutcome]:
    """Run every vector in the set through the verifier and compare against
    the published expectations (outcome, and for rejections the failing
    stage and code). Behavior probes are reported NOT_JUDGEABLE."""
    verifier = vector_set.make_verifier()
    outcomes: list[VectorOutcome] = []
    for vec in vector_set.data["vectors"]:
        vector_id = str(vec["id"])
        if vec.get("mode") == "probe" or vec.get("kind") == "negative-behavior":
            expect = vec.get("expect") or {}
            outcomes.append(
                VectorOutcome(
                    vector_id=vector_id,
                    kind=str(vec["kind"]),
                    mode=str(vec["mode"]),
                    status="NOT_JUDGEABLE",
                    detail=(
                        f"behavior probe, subject={expect.get('subject')}: an artifact "
                        f"verifier cannot judge implementation behavior "
                        f"(expected NONCONFORMANT/{expect.get('failing_code')} if the "
                        "probed behavior occurs)"
                    ),
                )
            )
            continue
        artifact = vector_set.construct(vector_id)
        evaluation_results: list[dict] = []
        all_match = True
        for evaluation in artifact.evaluations:
            expect = evaluation["expect"]
            judgment: Judgment = verifier.verify(
                artifact.message_raw,
                int(evaluation["verify_time"]),
                paired_request_raw=artifact.paired_raw,
                expected_base=artifact.expected_bases,
            )
            match = judgment.verdict == expect["outcome"]
            if expect["outcome"] in ("REJECT", "CLIENT_REJECT"):
                match = (
                    match
                    and judgment.failing_stage == expect.get("failing_stage")
                    and judgment.failing_code == expect.get("failing_code")
                )
            all_match = all_match and match
            evaluation_results.append(
                {
                    "verify_time": evaluation["verify_time"],
                    "expected": expect,
                    "actual": {
                        "verdict": judgment.verdict,
                        "failing_stage": judgment.failing_stage,
                        "failing_code": judgment.failing_code,
                        "cascades": judgment.cascades,
                    },
                    "match": match,
                }
            )
        outcomes.append(
            VectorOutcome(
                vector_id=vector_id,
                kind=str(vec["kind"]),
                mode=str(vec["mode"]),
                status="MATCH" if all_match else "MISMATCH",
                evaluations=evaluation_results,
            )
        )
    return outcomes
