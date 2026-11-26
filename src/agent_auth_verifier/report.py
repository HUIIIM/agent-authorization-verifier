"""Reports: one shared model, rendered as JSON, Markdown or terminal text.

Design section 4.3. A report is built ONCE, as a plain-data model (dicts,
lists, strings, ints, bools, None), from the judgment layer's outputs
(``VectorOutcome`` and ``ContrastResult``). Every renderer -- ``render_json``,
``render_md``, ``render_text`` -- reads only that model, so the formats
cannot drift: a value that is not in the model cannot appear in any
format, and a value in the model appears in all of them.

The flow is one-way. This module imports the judgment layer's result
types; nothing in the judgment layer imports this module, and nothing
built here is passed back into a verifier call.

Determinism (W4):

* time: the only timestamp is ``meta.generated_at``, taken from the
  injected ``Clock``. Judgment times are the vectors' own ``verify_time``
  values, never a clock reading.
* canonical form: ``canonicalize`` drops the volatile ``meta`` envelope
  and sorts every collection by a stable key (vectors by natural id,
  evaluations by verify_time, reconciliation items by key); serialization
  sorts mapping keys, uses fixed separators, ASCII escapes and LF line
  endings with one trailing newline. Two runs over the same vector set
  therefore produce byte-identical canonical files, whatever the input
  order of the set, the process hash seed, or the wall-clock time.
* content addressing: inputs are identified by file name and digest, never
  by an absolute path.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .clock import Clock, format_instant
from .contrast import ContrastResult
from .vectors import VectorOutcome, VectorSet

SCHEMA = "aav-report/1"
DRAFT = "draft-ietf-wimse-http-signature-09"

#: Per-vector readings. MATCH and NOT_JUDGEABLE come straight from the
#: runner; a runner MISMATCH is split into the two classes the suite's
#: records use.
READING_MATCH = "MATCH"
READING_NOT_JUDGEABLE = "NOT_JUDGEABLE"
READING_ATTRIBUTION = "attribution-only"
READING_VERDICT = "verdict-divergence"


# -- helpers ------------------------------------------------------------------
_ID_RE = re.compile(r"^([A-Za-z]+)-(\d+)(.*)$")
_PREFIX_RANK = {"P": 0, "N": 1}


def vector_sort_key(vector_id: str) -> tuple:
    """Natural order of suite ids: P-01..P-06, then N-01, N-02, ..., N-09,
    N-09b, N-10, ... Independent of the order of the input file."""
    match = _ID_RE.match(vector_id)
    if not match:
        return (9, vector_id, 0, "")
    prefix, number, suffix = match.groups()
    return (_PREFIX_RANK.get(prefix, 2), prefix, int(number), suffix)


def _sha256_file(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _md5_file(path: str | Path) -> str:
    return hashlib.md5(Path(path).read_bytes()).hexdigest()


def classify_outcome(outcome: VectorOutcome) -> str:
    """The reading of one runner outcome.

    A MISMATCH whose every evaluation agrees on the layer-1 verdict (and
    differs only in primary stage/code) is ``attribution-only``; any
    verdict disagreement is a ``verdict-divergence``.
    """
    if outcome.status == "MATCH":
        return READING_MATCH
    if outcome.status == "NOT_JUDGEABLE":
        return READING_NOT_JUDGEABLE
    verdicts_agree = all(
        e["expected"]["outcome"] == e["actual"]["verdict"] for e in outcome.evaluations
    )
    return READING_ATTRIBUTION if verdicts_agree else READING_VERDICT


# -- selection ------------------------------------------------------------------
def vector_classes(vector_set: VectorSet) -> list[str]:
    """The vector classes of a set: the suite's ``kind`` values."""
    return sorted({str(v["kind"]) for v in vector_set.vectors.values()})


def select_ids(
    vector_set: VectorSet, *, vector_id: str | None = None, vector_class: str | None = None
) -> list[str]:
    """Resolve a selection to vector ids (natural order).

    No argument -> every vector; ``vector_id`` -> that one vector;
    ``vector_class`` -> every vector whose ``kind`` equals it. Unknown ids
    and classes raise ``KeyError`` naming what exists.
    """
    ids = sorted(vector_set.vectors, key=vector_sort_key)
    if vector_id is not None:
        if vector_id not in vector_set.vectors:
            raise KeyError(f"unknown vector id {vector_id!r}; known: {', '.join(ids)}")
        return [vector_id]
    if vector_class is not None:
        classes = vector_classes(vector_set)
        if vector_class not in classes:
            raise KeyError(f"unknown vector class {vector_class!r}; known: {', '.join(classes)}")
        return [i for i in ids if vector_set.vectors[i]["kind"] == vector_class]
    return ids


# -- model --------------------------------------------------------------------
def _vector_entry(outcome: VectorOutcome) -> dict[str, Any]:
    evaluations = [
        {
            "verify_time": int(e["verify_time"]),
            "expected": dict(e["expected"]),
            "actual": {
                "verdict": e["actual"]["verdict"],
                "failing_stage": e["actual"]["failing_stage"],
                "failing_code": e["actual"]["failing_code"],
                "cascades": list(e["actual"]["cascades"]),
            },
            "match": bool(e["match"]),
        }
        for e in outcome.evaluations
    ]
    return {
        "id": outcome.vector_id,
        "kind": outcome.kind,
        "mode": outcome.mode,
        "status": outcome.status,
        "reading": classify_outcome(outcome),
        "detail": outcome.detail,
        "evaluations": evaluations,
    }


def _contrast_entry(result: ContrastResult, source: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": result.vector_id,
        "source": dict(source),
        "verdict": result.verdict,
        "anomalies": list(result.anomalies),
        "legs": [
            {
                "verify_time": leg.verify_time,
                "verdict": leg.judgment.verdict,
                "failing_stage": leg.judgment.failing_stage,
                "failing_code": leg.judgment.failing_code,
                "match": leg.match,
                "mismatches": list(leg.mismatches),
            }
            for leg in result.legs
        ],
        "table": [
            {
                "step": row.step,
                "label": row.label,
                "invariant": row.invariant,
                "statuses": list(row.statuses),
                "codes": list(row.codes),
            }
            for row in result.table
        ],
    }


def contrast_source(path: str | Path) -> dict[str, Any]:
    """Content-addressed identity of a contrast vector file: name, MD5,
    and whether the MD5 equals the one a sibling ``catalog.json`` records
    (None when there is no catalog entry)."""
    path = Path(path)
    md5 = _md5_file(path)
    catalog_md5 = None
    catalog = path.parent / "catalog.json"
    if catalog.is_file():
        files = json.loads(catalog.read_text(encoding="utf-8")).get("files", {})
        catalog_md5 = (files.get(path.name) or {}).get("md5")
    return {
        "file": f"{path.parent.name}/{path.name}",
        "md5": md5,
        "catalog_md5_match": None if catalog_md5 is None else catalog_md5 == md5,
    }


def _summary(vectors: list[dict[str, Any]], contrast: list[dict[str, Any]]) -> dict[str, Any]:
    by_reading: dict[str, list[str]] = {}
    for v in vectors:
        by_reading.setdefault(v["reading"], []).append(v["id"])
    return {
        "total": len(vectors),
        "matched": sum(v["status"] == "MATCH" for v in vectors),
        "mismatched": sum(v["status"] == "MISMATCH" for v in vectors),
        "not_judgeable": sum(v["status"] == "NOT_JUDGEABLE" for v in vectors),
        "readings": {k: sorted(ids, key=vector_sort_key) for k, ids in by_reading.items()},
        "contrast_pass": sum(c["verdict"] == "pass" for c in contrast),
        "contrast_fail": sum(c["verdict"] != "pass" for c in contrast),
    }


def _reconcile(
    baseline: dict[str, Any],
    baseline_source: dict[str, Any],
    vectors: list[dict[str, Any]],
    contrast: list[dict[str, Any]],
    full_selection: bool,
    set_md5: str,
) -> dict[str, Any]:
    """Compare live readings with a recorded baseline, item by item.

    The baseline is read, never written. Aggregate counts are compared
    over the selected vectors (for a partial selection the expected counts
    are derived from the baseline's per-vector readings of those vectors).
    """
    recorded: dict[str, str] = dict(baseline.get("readings", {}))
    items: list[dict[str, Any]] = []

    def add(key: str, expected: Any, live: Any) -> None:
        items.append(
            {
                "key": key,
                "expected": expected,
                "live": live,
                "status": "match" if expected == live else "DIVERGENT",
            }
        )

    if baseline.get("set_md5") is not None:
        add("set.md5", baseline["set_md5"], set_md5)
    selected = [v["id"] for v in vectors]
    if full_selection and "summary" in baseline:
        expected_counts = dict(baseline["summary"])
    else:
        exp_readings = [recorded.get(i) for i in selected]
        expected_counts = {
            "matched": sum(r == READING_MATCH for r in exp_readings),
            "mismatched": sum(r in (READING_ATTRIBUTION, READING_VERDICT) for r in exp_readings),
            "not_judgeable": sum(r == READING_NOT_JUDGEABLE for r in exp_readings),
        }
    live_counts = {
        "matched": sum(v["status"] == "MATCH" for v in vectors),
        "mismatched": sum(v["status"] == "MISMATCH" for v in vectors),
        "not_judgeable": sum(v["status"] == "NOT_JUDGEABLE" for v in vectors),
    }
    for name in ("matched", "mismatched", "not_judgeable"):
        add(f"summary.{name}", expected_counts.get(name), live_counts[name])
    for v in vectors:
        add(f"vector.{v['id']}", recorded.get(v["id"]), v["reading"])
    for c in contrast:
        expected = baseline.get("contrast", {}).get(c["id"])
        if expected is None:
            add(f"contrast.{c['id']}", None, {"verdict": c["verdict"]})
            continue
        add(
            f"contrast.{c['id']}",
            {"verdict": expected.get("verdict"), "anomalies": expected.get("anomalies")},
            {"verdict": c["verdict"], "anomalies": len(c["anomalies"])},
        )
    divergences = [i["key"] for i in items if i["status"] != "match"]
    return {"baseline": dict(baseline_source), "items": items, "divergences": divergences}


def build_report(
    vector_set: VectorSet,
    set_path: str | Path,
    outcomes: Iterable[VectorOutcome],
    *,
    selection: dict[str, Any],
    clock: Clock,
    contrast: Iterable[tuple[ContrastResult, dict[str, Any]]] = (),
    baseline: dict[str, Any] | None = None,
    baseline_source: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the one report model every format is rendered from.

    ``outcomes`` are the runner's results for the selected vectors;
    ``contrast`` pairs each contrast result with its ``contrast_source``.
    The clock is read exactly once, for ``meta.generated_at``.
    """
    from . import __version__

    set_path = Path(set_path)
    set_md5 = _md5_file(set_path)
    vectors = sorted((_vector_entry(o) for o in outcomes), key=lambda v: vector_sort_key(v["id"]))
    contrast_entries = sorted(
        (_contrast_entry(r, s) for r, s in contrast), key=lambda c: vector_sort_key(c["id"])
    )
    body: dict[str, Any] = {
        "schema": SCHEMA,
        "tool": {"name": "agent-authorization-verifier", "version": __version__, "draft": DRAFT},
        "set": {
            "file": set_path.name,
            "md5": set_md5,
            "sha256": _sha256_file(set_path),
            "set_version": vector_set.set_version,
            "draft_version": vector_set.draft_version,
        },
        "selection": dict(selection),
        "vectors": vectors,
        "contrast": contrast_entries,
        "summary": _summary(vectors, contrast_entries),
        "reconciliation": None,
    }
    if baseline is not None:
        body["reconciliation"] = _reconcile(
            baseline,
            baseline_source or {},
            vectors,
            contrast_entries,
            selection.get("mode") == "all",
            set_md5,
        )
    return {"meta": {"generated_at": format_instant(clock.now())}, **body}


def load_baseline(path: str | Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """Read a baseline file; return it and its content-addressed identity."""
    path = Path(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    return data, {"file": f"{path.parent.name}/{path.name}", "sha256": _sha256_file(path)}


# -- normalization ----------------------------------------------------------------
def canonicalize(model: dict[str, Any]) -> dict[str, Any]:
    """The canonical report body: the model without its volatile ``meta``
    envelope, with every collection in a stable order. Idempotent."""
    body = copy.deepcopy({k: v for k, v in model.items() if k != "meta"})
    body["vectors"].sort(key=lambda v: vector_sort_key(v["id"]))
    for v in body["vectors"]:
        v["evaluations"].sort(key=lambda e: e["verify_time"])
    body["contrast"].sort(key=lambda c: vector_sort_key(c["id"]))
    for c in body["contrast"]:
        c["legs"].sort(key=lambda leg: leg["verify_time"])
    for ids in body["summary"]["readings"].values():
        ids.sort(key=vector_sort_key)
    rec = body.get("reconciliation")
    if rec is not None:
        rec["items"].sort(key=lambda i: i["key"])
        rec["divergences"].sort()
    return body


def fingerprint(text: str) -> str:
    """SHA-256 of a rendered report's exact bytes (UTF-8)."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# -- renderers ------------------------------------------------------------------
def render_json(model: dict[str, Any]) -> str:
    """JSON rendering: sorted keys, 2-space indent, ASCII, LF, final newline."""
    return json.dumps(model, sort_keys=True, indent=2, ensure_ascii=True) + "\n"


def _cell(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (dict, list)):
        return "`" + json.dumps(value, sort_keys=True, separators=(",", ":")) + "`"
    return str(value).replace("|", "\\|").replace("\n", " ")


def _expected_text(expected: dict[str, Any]) -> str:
    outcome = expected.get("outcome")
    if outcome == "ACCEPT" or outcome is None:
        return str(outcome)
    return f"{outcome} {expected.get('failing_stage')}/{expected.get('failing_code')}"


def _actual_text(actual: dict[str, Any]) -> str:
    if actual["verdict"] == "ACCEPT":
        return "ACCEPT"
    text = f"{actual['verdict']} {actual['failing_stage']}/{actual['failing_code']}"
    if actual["cascades"]:
        text += f" (cascades: {', '.join(actual['cascades'])})"
    return text


def render_md(model: dict[str, Any]) -> str:
    """Markdown rendering of the same model (LF, final newline)."""
    lines: list[str] = []
    s = model["set"]
    tool = model["tool"]
    sel = model["selection"]
    lines += [
        f"# Vector run report: set {s['set_version']}",
        "",
        f"- Schema: `{model['schema']}`",
        f"- Tool: {tool['name']} {tool['version']} ({tool['draft']})",
        (
            f"- Set: `{s['file']}` (set {s['set_version']}, draft {s['draft_version']}); "
            f"MD5 `{s['md5']}`; SHA-256 `{s['sha256']}`"
        ),
        f"- Selection: {sel['mode']}" + (f" = `{sel['value']}`" if sel.get("value") else ""),
    ]
    if "meta" in model:
        lines.append(f"- Generated at: {model['meta']['generated_at']}")
    summ = model["summary"]
    lines += [
        "",
        "## Summary",
        "",
        "| Total | Matched | Mismatched | Not judgeable | Contrast pass | Contrast fail |",
        "| --- | --- | --- | --- | --- | --- |",
        (
            f"| {summ['total']} | {summ['matched']} | {summ['mismatched']} | "
            f"{summ['not_judgeable']} | {summ['contrast_pass']} | {summ['contrast_fail']} |"
        ),
        "",
        "| Reading | Vectors |",
        "| --- | --- |",
        *[f"| {reading} | {', '.join(ids)} |" for reading, ids in sorted(summ["readings"].items())],
        "",
        "## Vectors",
        "",
        "| Vector | Kind | Mode | t | Expected | Actual | Match | Reading |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for v in model["vectors"]:
        if not v["evaluations"]:
            lines.append(
                f"| {v['id']} | {v['kind']} | {v['mode']} | - | - | - | - | {v['reading']} |"
            )
            continue
        for e in v["evaluations"]:
            lines.append(
                f"| {v['id']} | {v['kind']} | {v['mode']} | {e['verify_time']} | "
                f"{_cell(_expected_text(e['expected']))} | {_cell(_actual_text(e['actual']))} | "
                f"{_cell(e['match'])} | {v['reading']} |"
            )
    notes = [v for v in model["vectors"] if v["detail"]]
    if notes:
        lines += ["", "Notes:", ""]
        lines += [f"- {v['id']}: {v['detail']}" for v in notes]
    if model["contrast"]:
        lines += ["", "## Contrast surface", ""]
    for c in model["contrast"]:
        src = c["source"]
        lines += [
            f"### {c['id']}: {c['verdict']}",
            "",
            f"Source: `{src['file']}` (MD5 `{src['md5']}`; catalog MD5 match: "
            f"{_cell(src['catalog_md5_match'])}). Anomalies: "
            + ("; ".join(c["anomalies"]) if c["anomalies"] else "none")
            + ".",
            "",
            "| Step | Label | Invariant | "
            + " | ".join(f"t={leg['verify_time']}" for leg in c["legs"])
            + " |",
            "| --- | --- | --- | " + " | ".join("---" for _ in c["legs"]) + " |",
        ]
        for row in c["table"]:
            cells = [
                st + (f" ({code})" if code else "")
                for st, code in zip(row["statuses"], row["codes"], strict=True)
            ]
            lines.append(
                f"| {row['step']} | {row['label']} | {_cell(row['invariant'])} | "
                + " | ".join(cells)
                + " |"
            )
        lines.append("")
        for leg in c["legs"]:
            lines.append(
                f"- t={leg['verify_time']}: {leg['verdict']}"
                + (f" {leg['failing_stage']}/{leg['failing_code']}" if leg["failing_stage"] else "")
                + f"; match: {_cell(leg['match'])}"
                + (f"; mismatches: {'; '.join(leg['mismatches'])}" if leg["mismatches"] else "")
            )
    rec = model["reconciliation"]
    lines += ["", "## Reconciliation against the recorded baseline", ""]
    if rec is None:
        lines.append("No baseline given.")
    else:
        b = rec["baseline"]
        lines += [
            f"Baseline: `{b.get('file')}` (SHA-256 `{b.get('sha256')}`).",
            "",
            "| Item | Expected (recorded) | Live | Status |",
            "| --- | --- | --- | --- |",
            *[
                f"| {i['key']} | {_cell(i['expected'])} | {_cell(i['live'])} | "
                + ("match" if i["status"] == "match" else "**DIVERGENT**")
                + " |"
                for i in rec["items"]
            ],
            "",
            "Divergences: "
            + (", ".join(rec["divergences"]) if rec["divergences"] else "none")
            + ".",
        ]
    return "\n".join(lines) + "\n"


def render_text(model: dict[str, Any]) -> str:
    """Terminal rendering of the same model (the ``run`` command)."""
    lines: list[str] = []
    for v in model["vectors"]:
        line = f"{v['id']:<6} {v['status']}"
        if v["reading"] not in (READING_MATCH, READING_NOT_JUDGEABLE):
            line += f" [{v['reading']}]"
        if v["detail"]:
            line += f"  -- {v['detail']}"
        lines.append(line)
        for e in v["evaluations"]:
            lines.append(
                f"       t={e['verify_time']}: expected {_expected_text(e['expected'])}, "
                f"got {_actual_text(e['actual'])} -> {'match' if e['match'] else 'MISMATCH'}"
            )
    for c in model["contrast"]:
        lines.append(
            f"contrast {c['id']} ({c['source']['file']}): {c['verdict']}; anomalies: "
            + ("; ".join(c["anomalies"]) if c["anomalies"] else "none")
        )
        for row in c["table"]:
            lines.append(f"       step {row['step']:<5} {' | '.join(row['statuses'])}")
    s = model["summary"]
    lines.append(
        f"summary: {s['matched']} matched, {s['mismatched']} mismatched, "
        f"{s['not_judgeable']} not judgeable by an artifact verifier "
        f"(set {model['set']['set_version']}, {model['set']['draft_version']}); "
        f"selection {model['selection']['mode']}"
        + (f"={model['selection']['value']}" if model["selection"].get("value") else "")
    )
    rec = model["reconciliation"]
    if rec is not None:
        lines.append(
            "baseline: "
            + (
                "no divergences"
                if not rec["divergences"]
                else "DIVERGENT: "
                + "; ".join(
                    f"{i['key']} expected {_cell(i['expected'])} live {_cell(i['live'])}"
                    for i in rec["items"]
                    if i["status"] != "match"
                )
            )
        )
    return "\n".join(lines) + "\n"
