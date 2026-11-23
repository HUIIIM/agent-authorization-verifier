"""CLI surface: the verify face on a single artifact, and the
run-vectors face on the published set."""

import json
from pathlib import Path

from agent_auth_verifier.cli import main
from agent_auth_verifier.vectors import VectorSet

FIXTURE = Path(__file__).parent / "fixtures" / "vectors.json"


def _write_config(tmp_path: Path, vector_set: VectorSet) -> Path:
    trusted = vector_set.materials["trusted_config"]
    config = {
        "trusted_audiences": trusted["wimse_aud_trusted"],
        "issuer_anchor_jwk": trusted["issuer_anchor_jwk"],
        "known_keys": [
            {"name": k["name"], "alg": k["alg"], "public_jwk": k["public_jwk"]}
            for k in vector_set.materials["keys"]
        ],
    }
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    return path


def test_cli_verify_accepts_p01(tmp_path: Path, vector_set: VectorSet, capsys) -> None:
    config = _write_config(tmp_path, vector_set)
    message = tmp_path / "p01.txt"
    message.write_bytes(vector_set.base_message_raw("P-01").encode("utf-8"))
    code = main(
        [
            "verify",
            "--message",
            str(message),
            "--config",
            str(config),
            "--time",
            "1795000060",
            "--json",
        ]
    )
    assert code == 0
    out = json.loads(capsys.readouterr().out)
    assert out["verdict"] == "ACCEPT"
    assert out["failing_stage"] is None
    assert len(out["stages"]) == 12


def test_cli_verify_rejects_tampered_signature(
    tmp_path: Path, vector_set: VectorSet, capsys
) -> None:
    config = _write_config(tmp_path, vector_set)
    raw = vector_set.base_message_raw("P-01")
    tampered = raw.replace("flavor=vanilla", "flavor=chocolat")
    message = tmp_path / "tampered.txt"
    message.write_bytes(tampered.encode("utf-8"))
    code = main(
        [
            "verify",
            "--message",
            str(message),
            "--config",
            str(config),
            "--time",
            "1795000060",
        ]
    )
    assert code == 1
    out = capsys.readouterr().out
    assert "verdict: REJECT" in out
    assert "CRYPTO" in out


def test_cli_run_vectors_summary(capsys) -> None:
    code = main(["run-vectors", "--set", str(FIXTURE)])
    out = capsys.readouterr().out
    # N-09 is the one documented divergence (see test_vectors.py), so the
    # strict comparison exits 1 with exactly one mismatch.
    assert code == 1
    assert "22 matched, 1 mismatched, 6 not judgeable" in out
