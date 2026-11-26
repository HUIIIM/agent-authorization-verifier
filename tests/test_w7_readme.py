"""W7 guards: README contract wording, README command annotations,
examples provenance, and the VERSION-MAP append-only rule.

These only check documents and example data; no judgment is involved.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
from pathlib import Path

from agent_auth_verifier.vectors import VectorSet

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"


def _flat(text: str) -> str:
    return " ".join(text.split())


# W4 contract wording (README at merge d4b5768), preserved verbatim up to
# line wrapping.
W4_RUN_EXIT_STATUS = """`run` exit status: with `--baseline`, 0 when every live reading equals the
recorded baseline (`baselines/s01-v4.json`) and 1 when any reading
diverges; without it, 0 only when every judgeable vector matches its
published expectation (so N-09's documented divergence exits 1, as
`run-vectors` does). An unknown id or class exits 2. `--contrast FILE`
also runs that contrast vector through the contrast engine (stepwise
table, CONTRAST_ANOMALY check) when its vector is selected."""
W4_CLASS_DOMAIN = "positive | negative-message | negative-behavior"
W4_REPORT = """`report` builds one plain-data model and renders it as either format, so
JSON and Markdown cannot drift. The only timestamp, `meta.generated_at`,
comes from the injected clock; the judgment path reads no clock at all
(time enters only as each evaluation's `verify_time`). `--canonical`
drops the `meta` envelope and normalizes key order and collection order,
so two runs over the same vector set give byte-identical files."""


def test_readme_keeps_w4_contract_wording() -> None:
    text = _flat(README.read_text(encoding="utf-8"))
    for snippet in (W4_RUN_EXIT_STATUS, W4_CLASS_DOMAIN, W4_REPORT):
        assert _flat(snippet) in text


def test_readme_has_the_four_w7_sections() -> None:
    headings = re.findall(r"^## (.+)$", README.read_text(encoding="utf-8"), re.MULTILINE)
    for name in ("Sources", "Citations", "Private-key warning", "How to run"):
        assert name in headings


def _check_readme_module():
    spec = importlib.util.spec_from_file_location("check_readme", ROOT / "scripts/check_readme.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_every_readme_command_block_is_annotated() -> None:
    mod = _check_readme_module()
    blocks = mod.parse_blocks(README.read_text(encoding="utf-8"))
    runnable = [b for b in blocks if b["lang"] in mod.RUNNABLE]
    assert runnable
    for b in runnable:
        assert b["annot"] is not None, f"README.md:{b['line']} has no readme-check annotation"
        mod.parse_annotation(b["annot"].group(1))
    # No placeholder commands: every printed command must run literally.
    for b in runnable:
        assert "..." not in b["body"], f"README.md:{b['line']} has a placeholder"


def test_examples_are_the_fixture_artifacts(vector_set: VectorSet) -> None:
    for vid in ("P-01", "N-10"):
        path = ROOT / "examples" / f"{vid.lower()}-request.http"
        assert path.read_bytes() == vector_set.construct(vid).message_raw.encode("utf-8")
    config = json.loads((ROOT / "examples" / "trusted-config.json").read_text(encoding="utf-8"))
    trusted = vector_set.materials["trusted_config"]
    assert config["trusted_audiences"] == trusted["wimse_aud_trusted"]
    assert config["issuer_anchor_jwk"] == trusted["issuer_anchor_jwk"]
    assert config["known_keys"] == [
        {"name": k["name"], "alg": k["alg"], "public_jwk": k["public_jwk"]}
        for k in vector_set.materials["keys"]
    ]


def test_examples_hold_no_private_key_material() -> None:
    for path in (ROOT / "examples").iterdir():
        text = path.read_text(encoding="utf-8")
        assert "private" not in text.lower()
        assert '"d":' not in text


# The rows registered at W7. VERSION-MAP.md is append-only: these rows must
# stay byte-identical and first; later waves only add rows after them.
W7_ROWS_SHA256 = "ec9743868a09a7e1c172cd4e072bf0854cfb55a967a58792098cb7d4957e0bcd"
W7_ROW_COUNT = 2


def test_version_map_w7_rows_unchanged() -> None:
    text = (ROOT / "VERSION-MAP.md").read_text(encoding="utf-8")
    rows = [line for line in text.splitlines() if re.match(r"^\| M-\d+ ", line)]
    assert [r.split("|")[1].strip() for r in rows] == [f"M-{i}" for i in range(1, len(rows) + 1)]
    head = "\n".join(rows[:W7_ROW_COUNT]) + "\n"
    assert hashlib.sha256(head.encode("utf-8")).hexdigest() == W7_ROWS_SHA256
