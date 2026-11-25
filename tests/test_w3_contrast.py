"""W3: WIT pre-checks per design section 3.2 and the N-09b contrast engine."""

import copy
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from agent_auth_verifier import (
    CONTRAST_ANOMALY,
    VectorSet,
    check_anomalies,
    run_contrast,
    run_contrast_from_file,
)
from agent_auth_verifier.crypto import b64u_encode, sign
from agent_auth_verifier.wit import WitError, validate_wit, wit_steps

T0 = 1795000000
REPO_ROOT = Path(__file__).resolve().parents[1]

#: The section 2.2 stepwise table for N-09b, from the source piece:
#: step -> (leg at T0+300, leg at T0+301).
SOURCE_TABLE = {
    "1": ("pass", "pass"),
    "1b": ("pass", "pass"),
    "1c": ("pass", "pass"),
    "2": ("pass", "pass"),
    "3": ("pass", "pass"),
    "4": ("pass", "pass"),
    "5": ("pass", "fail"),
    "final": ("ACCEPT", "REJECT"),
}


def _ed25519_anchor():
    """A fresh Ed25519 issuer anchor (private key object + public JWK)."""
    private = ed25519.Ed25519PrivateKey.generate()
    public = private.public_key()
    raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    public_jwk = {"kty": "OKP", "crv": "Ed25519", "alg": "Ed25519", "x": b64u_encode(raw)}
    return private, public_jwk


def _make_wit(
    private, public_jwk, *, typ="wit+jwt", exp=T0 + 3600, cnf=True, with_alg=True, iat=None
):
    """Build a WIT signed by the test anchor (typ/cnf/exp/iat adjustable)."""
    header = {"alg": "Ed25519"}
    if typ is not None:
        header["typ"] = typ
    claims: dict = {"sub": "wimse://example.com/test", "exp": exp}
    if iat is not None:
        claims["iat"] = iat
    if cnf:
        jwk = dict(public_jwk)
        if not with_alg:
            jwk.pop("alg", None)
        claims["cnf"] = {"jwk": jwk}
    header_b64 = b64u_encode(json.dumps(header, separators=(",", ":")).encode())
    claims_b64 = b64u_encode(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{claims_b64}".encode("ascii")
    signature = sign("Ed25519", private, signing_input)
    return f"{header_b64}.{claims_b64}.{b64u_encode(signature)}"


def _wit_a(vector_set):
    return vector_set.materials["wits"]["WIT-A"]["jws"]


def _anchor(vector_set):
    return vector_set.materials["trusted_config"]["issuer_anchor_jwk"]


def test_wit_typ_wrong_is_e_wit_type() -> None:
    """Design 3.2: typ other than wit+jwt fails with E_WIT_TYPE."""
    private, public_jwk = _ed25519_anchor()
    token = _make_wit(private, public_jwk, typ="JWT")
    with pytest.raises(WitError) as excinfo:
        validate_wit(token, public_jwk, T0 + 60)
    assert excinfo.value.code == "E_WIT_TYPE"


def test_wit_typ_missing_is_e_wit_type() -> None:
    """Design 3.2: a missing typ header fails with E_WIT_TYPE."""
    private, public_jwk = _ed25519_anchor()
    token = _make_wit(private, public_jwk, typ=None)
    with pytest.raises(WitError) as excinfo:
        validate_wit(token, public_jwk, T0 + 60)
    assert excinfo.value.code == "E_WIT_TYPE"


def test_wit_no_cnf_is_e_wit_cnf() -> None:
    """Design 3.2: a WIT without cnf fails with E_WIT_CNF."""
    private, public_jwk = _ed25519_anchor()
    token = _make_wit(private, public_jwk, cnf=False)
    with pytest.raises(WitError) as excinfo:
        validate_wit(token, public_jwk, T0 + 60)
    assert excinfo.value.code == "E_WIT_CNF"


def test_wit_cnf_without_alg_is_e_wit_cnf() -> None:
    """Draft 5.1/5.1.3: cnf.jwk must carry an alg member."""
    private, public_jwk = _ed25519_anchor()
    token = _make_wit(private, public_jwk, with_alg=False)
    with pytest.raises(WitError) as excinfo:
        validate_wit(token, public_jwk, T0 + 60)
    assert excinfo.value.code == "E_WIT_CNF"


def test_wit_malformed_is_e_wit_sig() -> None:
    """Design 3.2: an unparseable token cannot be verified (E_WIT_SIG)."""
    _, public_jwk = _ed25519_anchor()
    for token in ("not-a-jwt", "aaa.bbb", ""):
        with pytest.raises(WitError) as excinfo:
            validate_wit(token, public_jwk, T0 + 60)
        assert excinfo.value.code == "E_WIT_SIG"


def test_wit_future_iat_is_ignored() -> None:
    """Section 3.2 scope: iat is not a WIT pre-check (draft is silent too)."""
    private, public_jwk = _ed25519_anchor()
    token = _make_wit(private, public_jwk, iat=T0 + 7200)
    info = validate_wit(token, public_jwk, T0 + 60)
    assert info.subject == "wimse://example.com/test"


def test_wit_steps_n09b(vector_set: VectorSet) -> None:
    """WIT sub-steps for N-09b: all pass at T0+300; 1c fails at T0+3600."""
    token, anchor = _wit_a(vector_set), _anchor(vector_set)
    steps = {step.step: step for step in wit_steps(token, anchor, T0 + 300)}
    assert [steps[s].status for s in ("1", "1b", "1c")] == ["pass", "pass", "pass"]
    steps = {step.step: step for step in wit_steps(token, anchor, T0 + 3600)}
    assert [steps[s].status for s in ("1", "1b", "1c")] == ["pass", "pass", "fail"]
    assert steps["1c"].code == "E_WIT_EXP"


def test_n09b_stepwise_table_matches_source(vector_set: VectorSet) -> None:
    """Acceptance 1: N-09b two-leg verdicts and the section 2.2 table, cell by cell."""
    result = run_contrast(vector_set, "N-09b")
    assert result.verdict == "pass"
    assert result.anomalies == []
    assert [leg.verify_time for leg in result.legs] == [T0 + 300, T0 + 301]
    assert [leg.match for leg in result.legs] == [True, True]
    assert [leg.mismatches for leg in result.legs] == [[], []]
    rows = {row.step: row for row in result.table}
    for step, (leg1, leg2) in SOURCE_TABLE.items():
        assert rows[step].statuses == [leg1, leg2], f"step {step} differs from the source table"
    assert rows["5"].codes == [None, "E_WINDOW_OUTSIDE"]
    assert rows["final"].codes == [None, "E_WINDOW_OUTSIDE"]
    leg1, leg2 = result.legs
    assert leg1.judgment.verdict == "ACCEPT"
    assert leg2.judgment.verdict == "REJECT"
    assert leg2.judgment.failing_stage == "WINDOW"
    assert leg2.judgment.failing_code == "E_WINDOW_OUTSIDE"
    assert leg1.judgment.signature_base == leg2.judgment.signature_base
    assert leg1.judgment.cascades == [] and leg2.judgment.cascades == []


def test_n09b_legs_run_independently(
    vector_set: VectorSet, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Section 2.5: each evaluation runs the full chain; no cross-leg caching."""
    from agent_auth_verifier.verifier import Verifier

    calls: list[int] = []
    original = Verifier.verify

    def counting_verify(self, message_raw, verify_time, *args, **kwargs):
        calls.append(verify_time)
        return original(self, message_raw, verify_time, *args, **kwargs)

    monkeypatch.setattr(Verifier, "verify", counting_verify)
    result = run_contrast(vector_set, "N-09b")
    assert result.verdict == "pass"
    assert calls == [T0 + 300, T0 + 301]
    first, second = result.legs
    assert first.judgment is not second.judgment
    assert first.judgment.stages is not second.judgment.stages
    assert first.steps["2"] is not second.steps["2"]


def test_n09b_contrast_block_matches_engine(vector_set: VectorSet) -> None:
    """The fixture's declared invariant stages agree across the N-09b legs."""
    entry = vector_set.vectors["N-09b"]
    declared = entry["contrast"]["time_invariant_stages"]
    engine_stages = {"WIT", "SELECT", "PARAMS", "COVERAGE", "BASE", "DIGEST", "CRYPTO", "AUD"}
    assert set(declared) <= engine_stages
    result = run_contrast(vector_set, "N-09b")
    for stage in ("SELECT", "BASE", "PARAMS", "COVERAGE", "CRYPTO", "AUD"):
        statuses = [leg.judgment.stage(stage).status for leg in result.legs]
        assert statuses == ["pass", "pass"], f"{stage} should agree across legs"
    # DIGEST does not apply to this message (no Content-Digest), so it is
    # "skip" in both legs -- agreement of the invariant, not a failure.
    assert [leg.judgment.stage("DIGEST").status for leg in result.legs] == [
        "skip",
        "skip",
    ]
    assert result.legs[0].steps["1"].status == result.legs[1].steps["1"].status == "pass"
    assert result.legs[0].steps["1b"].status == result.legs[1].steps["1b"].status == "pass"


def test_contrast_anomaly_injection(vector_set: VectorSet) -> None:
    """Acceptance 3: moving one leg past WIT expiry makes invariant steps diverge."""
    entry = vector_set.vectors["N-09b"]
    evaluations = copy.deepcopy(entry["evaluations"])
    evaluations[1]["verify_time"] = T0 + 3600
    evaluations[1]["expect"] = {
        "outcome": "REJECT",
        "failing_stage": "WIT",
        "failing_code": "E_WIT_EXP",
    }
    result = run_contrast(vector_set, "N-09b", evaluations=evaluations)
    assert result.legs[1].match, "the tampered leg matches its tampered expectation"
    assert result.verdict == "fail"
    assert result.anomalies
    assert all(a.startswith(CONTRAST_ANOMALY) for a in result.anomalies)
    assert any("step 2" in a for a in result.anomalies)
    assert result.legs[1].steps["1c"].status == "fail"
    assert result.legs[1].steps["2"].status == "blocked"


def test_check_anomalies_unit(vector_set: VectorSet) -> None:
    """Anomaly rule, isolated: only time-sensitive steps may differ."""
    result = run_contrast(vector_set, "N-09b")
    assert check_anomalies(result.legs) == []
    only_window = copy.deepcopy(result.legs)
    only_window[1].steps["5"].status = "pass"
    assert check_anomalies(only_window) == []
    only_wit_expiry = copy.deepcopy(result.legs)
    only_wit_expiry[1].steps["1c"].status = "fail"
    assert check_anomalies(only_wit_expiry) == []
    crypto_differs = copy.deepcopy(result.legs)
    crypto_differs[1].steps["2"].status = "fail"
    anomalies = check_anomalies(crypto_differs)
    assert len(anomalies) == 1 and anomalies[0].startswith(CONTRAST_ANOMALY)
    assert "step 2" in anomalies[0]


def test_v4_directory_n09b(vector_set: VectorSet) -> None:
    """vectors/v4/ holds the N-09b entry; the catalog counts match the set."""
    catalog = json.loads((REPO_ROOT / "vectors/v4/catalog.json").read_text())
    assert catalog["set_version"] == "v4"
    assert catalog["counts"] == {
        "total": 29,
        "positive": 6,
        "negative": 23,
        "negative_before_n09b": 22,
        "probe": 6,
        "judged": 23,
    }
    assert catalog["vectors"] == [entry["id"] for entry in vector_set.data["vectors"]]
    v4_entry = json.loads((REPO_ROOT / "vectors/v4/n-09b.json").read_text())
    assert v4_entry == vector_set.vectors["N-09b"]
    assert v4_entry["base_ref"] == "P-01"
    assert v4_entry["message"] == vector_set.vectors["P-01"]["message"]

    assert (
        catalog["files"]["n-09b.json"]["md5"]
        == hashlib.md5((REPO_ROOT / "vectors/v4/n-09b.json").read_bytes()).hexdigest()
    )
    result = run_contrast_from_file(REPO_ROOT / "vectors/v4/n-09b.json", vector_set)
    assert result.verdict == "pass"


def test_n09_probe_construction_matches_formula(vector_set: VectorSet) -> None:
    """Acceptance 2 (N-09): the probe message carries the window it is judged by."""
    artifact = vector_set.construct("N-09")
    message = artifact.message_raw
    assert "created=1795000000" in message
    assert "expires=1795000300" in message
    assert 'nonce="7f3a9c1e5b284d06a1f4e8c2b6d50937"' in message
    assert 'tag="wimse-workload-to-workload"' in message
    assert 'wimse-aud="https://svcb.example.com/gimme-ice-cream"' in message
    assert "workload-identity-token" in message
    verifier = vector_set.make_verifier()
    judgment = verifier.verify(message, T0 + 1800, artifact.paired_raw, artifact.expected_bases)
    assert judgment.verdict == "REJECT"
    assert judgment.failing_stage == "WINDOW"
    assert judgment.failing_code == "E_WINDOW_OUTSIDE"
    assert judgment.stage("WIT").status == "pass"
    assert judgment.stage("CRYPTO").status == "pass"


def test_n20_probe_construction_matches_formula(vector_set: VectorSet) -> None:
    """Acceptance 2 (N-20): expired WIT + valid message signature -> WIT-first rejection."""
    entry = vector_set.vectors["N-20"]
    assert entry["mode"] == "probe"
    assert entry["probe"]["subject"] == "verifier"
    assert entry["expect"] == {
        "outcome": "NONCONFORMANT",
        "subject": "verifier",
        "failing_code": "E_PROCESS_ORDER",
    }
    artifact = vector_set.construct("P-01")
    verifier = vector_set.make_verifier()
    accepted = verifier.verify(
        artifact.message_raw, T0 + 60, artifact.paired_raw, artifact.expected_bases
    )
    assert accepted.verdict == "ACCEPT"
    judgment = verifier.verify(
        artifact.message_raw, T0 + 3600, artifact.paired_raw, artifact.expected_bases
    )
    assert judgment.verdict == "REJECT"
    assert judgment.failing_stage == "WIT"
    assert judgment.failing_code == "E_WIT_EXP"
    assert judgment.stage("CRYPTO").status == "blocked"
    # SELECT only picks the signature parameters from parseable headers; it runs before the WIT check and passes even when the WIT is expired.
    assert judgment.stage("SELECT").status == "pass"
