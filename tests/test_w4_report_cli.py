"""W4: the section 4.2 command surface, section 4.3 dual-format reports
from one model, and the determinism hardening (clock injection, canonical
ordering)."""

from __future__ import annotations

import ast
import copy
import datetime as dt
import json
import random
import time
from pathlib import Path

import pytest

from agent_auth_verifier.cli import main
from agent_auth_verifier.clock import FixedClock, SystemClock, clock_from_spec
from agent_auth_verifier.contrast import run_contrast_from_file
from agent_auth_verifier.report import (
    build_report,
    canonicalize,
    contrast_source,
    fingerprint,
    load_baseline,
    render_json,
    render_md,
    select_ids,
)
from agent_auth_verifier.vectors import VectorSet, run_vector_set

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "agent_auth_verifier"
SET = ROOT / "tests" / "fixtures" / "vectors.json"
CONTRAST = ROOT / "vectors" / "v4" / "n-09b.json"
BASELINE = ROOT / "baselines" / "s01-v4.json"
COMMON = ["--set", str(SET), "--contrast", str(CONTRAST), "--baseline", str(BASELINE)]

#: Modules on the judgment path. They take time only as verify_time.
JUDGMENT_MODULES = (
    "components.py",
    "contrast.py",
    "crypto.py",
    "httpmsg.py",
    "sf.py",
    "vectors.py",
    "verifier.py",
    "wit.py",
)

#: Wall-clock reads, by attribute name (datetime.now, date.today,
#: time.time, ...).
WALL_CLOCK_ATTRS = {
    "now",
    "utcnow",
    "today",
    "time",
    "time_ns",
    "monotonic",
    "monotonic_ns",
    "perf_counter",
    "perf_counter_ns",
    "process_time",
    "localtime",
    "gmtime",
    "ctime",
}


def _model(clock=None, outcomes=None, **kw):
    vs = VectorSet.load(SET)
    result = run_contrast_from_file(CONTRAST, vs)
    baseline, source = load_baseline(BASELINE)
    return build_report(
        vs,
        SET,
        run_vector_set(vs) if outcomes is None else outcomes,
        selection=kw.get("selection", {"mode": "all", "value": None}),
        clock=clock or FixedClock(dt.datetime(2026, 11, 26, tzinfo=dt.UTC)),
        contrast=[(result, contrast_source(CONTRAST))],
        baseline=baseline,
        baseline_source=source,
    )


# -- section 4.2 command surface ---------------------------------------------------
def test_run_all_reconciles_with_baseline(capsys) -> None:
    code = main(["run", "--all", *COMMON])
    out = capsys.readouterr().out
    assert code == 0
    assert "22 matched, 1 mismatched, 6 not judgeable" in out
    assert "N-09   MISMATCH [attribution-only]" in out
    assert "contrast N-09b (v4/n-09b.json): pass; anomalies: none" in out
    assert "baseline: no divergences" in out


def test_run_all_without_baseline_is_strict(capsys) -> None:
    assert main(["run", "--all", "--set", str(SET)]) == 1


def test_run_id(capsys) -> None:
    code = main(["run", "--id", "N-09b", *COMMON, "--json"])
    body = json.loads(capsys.readouterr().out)
    assert code == 0
    assert [v["id"] for v in body["vectors"]] == ["N-09b"]
    assert [c["id"] for c in body["contrast"]] == ["N-09b"]
    assert body["selection"] == {"mode": "id", "value": "N-09b"}
    assert "meta" not in body


def test_run_id_excludes_unselected_contrast(capsys) -> None:
    main(["run", "--id", "P-01", *COMMON, "--json"])
    body = json.loads(capsys.readouterr().out)
    assert [v["id"] for v in body["vectors"]] == ["P-01"]
    assert body["contrast"] == []


def test_run_class(capsys) -> None:
    code = main(["run", "--class", "positive", *COMMON, "--json"])
    body = json.loads(capsys.readouterr().out)
    assert code == 0
    assert [v["id"] for v in body["vectors"]] == [f"P-0{i}" for i in range(1, 7)]
    assert body["summary"]["matched"] == 6


def test_run_unknown_id_and_class_exit_2(capsys) -> None:
    assert main(["run", "--id", "X-99", *COMMON]) == 2
    assert main(["run", "--class", "nope", *COMMON]) == 2
    err = capsys.readouterr().err
    assert "unknown vector id 'X-99'" in err
    assert "unknown vector class 'nope'" in err


def test_run_requires_exactly_one_selector() -> None:
    with pytest.raises(SystemExit) as none:
        main(["run", *COMMON])
    assert none.value.code == 2
    with pytest.raises(SystemExit) as both:
        main(["run", "--all", "--id", "P-01", *COMMON])
    assert both.value.code == 2


@pytest.mark.parametrize("fmt", ["json", "md"])
def test_report_formats(tmp_path: Path, fmt: str) -> None:
    out = tmp_path / f"r.{fmt}"
    args = ["report", "--format", fmt, *COMMON, "--clock", "2026-11-26T00:00:00Z"]
    assert main([*args, "--out", str(out)]) == 0
    text = out.read_text(encoding="utf-8")
    assert "2026-11-26T00:00:00Z" in text
    if fmt == "json":
        assert json.loads(text)["meta"]["generated_at"] == "2026-11-26T00:00:00Z"
    else:
        assert text.startswith("# Vector run report: set v4")


def test_select_ids_classes() -> None:
    vs = VectorSet.load(SET)
    assert len(select_ids(vs)) == 29
    assert len(select_ids(vs, vector_class="negative-behavior")) == 6
    assert len(select_ids(vs, vector_class="negative-message")) == 17


# -- section 4.3 one model, two formats --------------------------------------------
def test_json_and_md_render_the_same_model() -> None:
    model = canonicalize(_model())
    as_json = json.loads(render_json(model))
    assert as_json == model
    md = render_md(model)
    for v in model["vectors"]:
        assert f"| {v['id']} | {v['kind']} | {v['mode']} |" in md
    for reading, ids in model["summary"]["readings"].items():
        assert f"| {reading} | {', '.join(ids)} |" in md
    for item in model["reconciliation"]["items"]:
        assert f"| {item['key']} |" in md


def test_renderers_read_only_the_model() -> None:
    """A change made to the model shows up in both formats; nothing else
    feeds either renderer."""
    model = canonicalize(_model())
    edited = copy.deepcopy(model)
    edited["vectors"][0]["reading"] = "EDITED-READING"
    assert "EDITED-READING" in render_json(edited)
    assert "EDITED-READING" in render_md(edited)
    assert "EDITED-READING" not in render_json(model) + render_md(model)


# -- determinism ---------------------------------------------------------------------
def test_canonical_is_byte_identical_across_clocks_and_order() -> None:
    vs = VectorSet.load(SET)
    outcomes = run_vector_set(vs)
    shuffled = list(outcomes)
    random.Random(7).shuffle(shuffled)
    a = _model(clock=FixedClock(dt.datetime(2000, 1, 1, tzinfo=dt.UTC)), outcomes=outcomes)
    b = _model(clock=SystemClock(), outcomes=shuffled)
    assert a["meta"] != b["meta"]
    for render in (render_json, render_md):
        assert render(a) != render(b)
        assert fingerprint(render(canonicalize(a))) == fingerprint(render(canonicalize(b)))


def test_canonicalize_is_idempotent() -> None:
    once = canonicalize(_model())
    assert canonicalize(once) == once
    assert render_json(canonicalize(once)) == render_json(once)


def test_cli_canonical_reports_identical(tmp_path: Path) -> None:
    for i, clock in enumerate(["@0", "system"]):
        for fmt in ("json", "md"):
            out = tmp_path / f"{i}.{fmt}"
            main(
                ["report", "--format", fmt, *COMMON, "--canonical", "--clock", clock]
                + ["--out", str(out)]
            )
    for fmt in ("json", "md"):
        assert (tmp_path / f"0.{fmt}").read_bytes() == (tmp_path / f"1.{fmt}").read_bytes()
        assert b"generated_at" not in (tmp_path / f"0.{fmt}").read_bytes()
        assert b"Generated at" not in (tmp_path / f"0.{fmt}").read_bytes()


def test_clock_specs() -> None:
    assert clock_from_spec("@0").now() == dt.datetime(1970, 1, 1, tzinfo=dt.UTC)
    assert clock_from_spec("2026-11-26T01:02:03Z").now() == dt.datetime(
        2026, 11, 26, 1, 2, 3, tzinfo=dt.UTC
    )
    assert isinstance(clock_from_spec("system"), SystemClock)
    with pytest.raises(ValueError):
        FixedClock(dt.datetime.fromisoformat("2026-01-01T00:00:00"))  # naive on purpose


def test_judgment_path_reads_no_wall_clock(monkeypatch) -> None:
    """Run the full set and the contrast surface with the time module's
    clocks booby-trapped: any read on the judgment path would raise."""

    def trap(*_a, **_k):
        raise AssertionError("wall-clock read on the judgment path")

    for name in ("time", "time_ns", "monotonic", "perf_counter", "localtime", "gmtime"):
        monkeypatch.setattr(time, name, trap)
    vs = VectorSet.load(SET)
    outcomes = run_vector_set(vs)
    result = run_contrast_from_file(CONTRAST, vs)
    assert sum(o.status == "MATCH" for o in outcomes) == 22
    assert result.verdict == "pass"


def _is_clock_module(receiver: str) -> bool:
    """A receiver that is the time module or a datetime/date class (as
    opposed to an injected clock object such as ``clock``)."""
    last = receiver.split(".")[-1]
    return receiver == "time" or last in {"datetime", "date"}


def _injected_clock_reads(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return [
        f"{path.name}:{node.lineno}:{ast.unparse(node.func)}"
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "now"
        and not _is_clock_module(ast.unparse(node.func.value))
    ]


def _wall_clock_sites(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    sites = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in WALL_CLOCK_ATTRS
            and _is_clock_module(ast.unparse(node.func.value))
        ):
            sites.append(f"{path.name}:{node.lineno}:{ast.unparse(node.func)}")
        if isinstance(node, ast.Import) and any(a.name == "time" for a in node.names):
            sites.append(f"{path.name}:{node.lineno}:import time")
        if isinstance(node, ast.ImportFrom) and node.module == "time":
            sites.append(f"{path.name}:{node.lineno}:from time import")
    return sites


def test_only_the_clock_provider_reads_the_wall_clock() -> None:
    sites = {p.name: _wall_clock_sites(p) for p in sorted(SRC.glob("*.py"))}
    offenders = {name: s for name, s in sites.items() if s and name != "clock.py"}
    assert offenders == {}
    assert [x.split(":", 2)[2] for x in sites["clock.py"]] == ["_dt.datetime.now"]
    # The one injected-clock read: the report stamp, outside the judgment path.
    injected = [r for p in sorted(SRC.glob("*.py")) for r in _injected_clock_reads(p)]
    assert [r.split(":")[0] for r in injected] == ["report.py"]


def test_judgment_path_does_not_import_report_layer() -> None:
    """One-way flow: no judgment module imports the clock, report or CLI,
    and nothing under src/ imports selfcheck (section 4.6)."""
    for path in sorted(SRC.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Import, ast.ImportFrom)):
                continue
            mods = [a.name for a in node.names]
            if isinstance(node, ast.ImportFrom):
                mods = [node.module or ""] + mods
            assert not any(m.split(".")[0] in {"selfcheck", "run_selfcheck"} for m in mods), path
            if path.name in JUDGMENT_MODULES:
                assert not any(m.split(".")[-1] in {"clock", "report", "cli"} for m in mods), (
                    path.name,
                    mods,
                )


# -- reconciliation ---------------------------------------------------------------
def test_reconciliation_names_each_divergence(tmp_path: Path) -> None:
    """A baseline that disagrees with the live run is reported item by
    item; the baseline file itself is never rewritten."""
    data = json.loads(BASELINE.read_text(encoding="utf-8"))
    data["readings"]["N-09"] = "MATCH"
    data["summary"]["matched"] = 23
    edited = tmp_path / "edited.json"
    edited.write_text(json.dumps(data), encoding="utf-8")
    before = edited.read_bytes()
    code = main(["run", "--all", "--set", str(SET), "--baseline", str(edited), "--json"])
    assert code == 1
    assert edited.read_bytes() == before


def test_reconciliation_against_recorded_baseline() -> None:
    rec = _model()["reconciliation"]
    assert rec["divergences"] == []
    items = {i["key"]: i for i in rec["items"]}
    assert items["summary.matched"]["live"] == 22
    assert items["summary.not_judgeable"]["live"] == 6
    assert items["vector.N-09"]["live"] == "attribution-only"
    assert items["vector.N-09b"]["live"] == "MATCH"
    assert items["contrast.N-09b"]["live"] == {"verdict": "pass", "anomalies": 0}
