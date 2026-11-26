"""Command line interface.

Two faces over the same core:

  aav verify --message MSG.txt [--paired REQ.txt] --config CONFIG.json
             --time UNIX [--json]
      Judge one artifact (an HTTP request, or a response together with its
      paired request). Prints the two-layer judgment: the verdict, and the
      twelve-stage classification behind it.

  aav run-vectors --set vectors.json [--json]
      Run a published WIMSE HTTP signature test vector set through the
      verifier and compare every judged vector against its published
      expectation. Exit status is 0 when every judgeable vector matches.

  aav run (--all | --id VECTOR-ID | --class CLASS) --set vectors.json
          [--contrast FILE ...] [--baseline FILE] [--json]
      Run a selection of a vector set (design section 4.2): every vector,
      one vector by id, or every vector of one class (the suite's ``kind``:
      positive, negative-message, negative-behavior). Contrast files
      (e.g. vectors/v4/n-09b.json) are also run through the contrast engine
      when their vector is selected. Exit status: with --baseline, 0 when
      every live reading equals the recorded baseline and 1 otherwise; without
      it, 0 when every judgeable vector matches and 1 otherwise. An unknown id
      or class exits 2.

  aav report --format json|md --set vectors.json
             [--all | --id VECTOR-ID | --class CLASS] [--contrast FILE ...]
             [--baseline FILE] [--clock system|@UNIX|ISO8601] [--canonical]
             [--out PATH]
      Build the report model once and render it as JSON or Markdown
      (design section 4.3). The only timestamp, meta.generated_at, comes
      from the injected clock (--clock, default the system clock).
      --canonical drops that volatile envelope and normalizes ordering, so
      two runs over the same set produce byte-identical files. Exit status
      0 when the report was written (the run command is the gate).

The config file is JSON: {"trusted_audiences": [...], "issuer_anchor_jwk":
{...}, "known_keys": [{"name": ..., "alg": ..., "public_jwk": {...}}]}
(known_keys is optional and only refines failure classification).
No network access is performed by any command.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .clock import clock_from_spec
from .contrast import load_contrast_vector, run_contrast
from .report import (
    build_report,
    canonicalize,
    contrast_source,
    load_baseline,
    render_json,
    render_md,
    render_text,
    select_ids,
)
from .vectors import VectorSet, run_vector_set
from .verifier import Judgment, KnownKey, TrustedConfig, Verifier


def _load_config(path: str) -> tuple[TrustedConfig, list[KnownKey]]:
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    config = TrustedConfig(
        trusted_audiences=list(data["trusted_audiences"]),
        issuer_anchor_jwk=dict(data["issuer_anchor_jwk"]),
    )
    known = [
        KnownKey(name=k["name"], alg=k["alg"], public_jwk=dict(k["public_jwk"]))
        for k in data.get("known_keys", [])
    ]
    return config, known


def _print_judgment(judgment: Judgment) -> None:
    print(f"verdict: {judgment.verdict} (role: {judgment.role})")
    if judgment.failing_stage is not None:
        print(f"failing stage: {judgment.failing_stage} / {judgment.failing_code}")
    if judgment.cascades:
        print(f"cascading failures: {', '.join(judgment.cascades)}")
    if judgment.selected_label is not None:
        print(f"selected signature: {judgment.selected_label}")
    if judgment.wit_subject is not None:
        print(f"wit subject: {judgment.wit_subject}")
    print("stages:")
    for stage in judgment.stages:
        line = f"  {stage.stage:<9} {stage.status}"
        if stage.code:
            line += f"  {stage.code}"
        if stage.detail:
            line += f"  -- {stage.detail}"
        print(line)
    for note in judgment.notes:
        print(f"note: {note}")


def _read_wire(path: str) -> str:
    """Read a message file preserving CRLF line endings exactly (text-mode
    newline translation would destroy the wire format)."""
    return Path(path).read_bytes().decode("utf-8", errors="surrogateescape")


def _cmd_verify(args: argparse.Namespace) -> int:
    config, known = _load_config(args.config)
    verifier = Verifier(config, known_keys=known)
    message = _read_wire(args.message)
    paired = _read_wire(args.paired) if args.paired else None
    judgment = verifier.verify(message, args.time, paired_request_raw=paired)
    if args.json:
        print(json.dumps(judgment.to_dict(), indent=2))
    else:
        _print_judgment(judgment)
    return 0 if judgment.verdict == "ACCEPT" else 1


def _cmd_run_vectors(args: argparse.Namespace) -> int:
    vector_set = VectorSet.load(args.set)
    outcomes = run_vector_set(vector_set)
    if args.only:
        outcomes = [o for o in outcomes if o.vector_id in args.only]
    matched = sum(1 for o in outcomes if o.status == "MATCH")
    mismatched = [o for o in outcomes if o.status == "MISMATCH"]
    not_judgeable = [o for o in outcomes if o.status == "NOT_JUDGEABLE"]
    if args.json:
        print(
            json.dumps(
                [
                    {
                        "vector": o.vector_id,
                        "kind": o.kind,
                        "mode": o.mode,
                        "status": o.status,
                        "detail": o.detail,
                        "evaluations": o.evaluations,
                    }
                    for o in outcomes
                ],
                indent=2,
            )
        )
    else:
        for outcome in outcomes:
            line = f"{outcome.vector_id:<6} {outcome.status}"
            if outcome.detail:
                line += f"  -- {outcome.detail}"
            print(line)
            for evaluation in outcome.evaluations:
                actual = evaluation["actual"]
                expected = evaluation["expected"]
                print(
                    f"       t={evaluation['verify_time']}: expected "
                    f"{expected['outcome']}"
                    + (
                        f"/{expected.get('failing_stage')}/{expected.get('failing_code')}"
                        if expected["outcome"] != "ACCEPT"
                        else ""
                    )
                    + f", got {actual['verdict']}"
                    + (
                        f"/{actual['failing_stage']}/{actual['failing_code']}"
                        if actual["verdict"] != "ACCEPT"
                        else ""
                    )
                    + f" -> {'match' if evaluation['match'] else 'MISMATCH'}"
                )
        print(
            f"summary: {matched} matched, {len(mismatched)} mismatched, "
            f"{len(not_judgeable)} not judgeable by an artifact verifier "
            f"(set {vector_set.set_version}, {vector_set.draft_version})"
        )
    return 1 if mismatched else 0


def _selection(args: argparse.Namespace) -> dict:
    if getattr(args, "id", None) is not None:
        return {"mode": "id", "value": args.id}
    if getattr(args, "vector_class", None) is not None:
        return {"mode": "class", "value": args.vector_class}
    return {"mode": "all", "value": None}


def _build_model(args: argparse.Namespace, clock_spec: str) -> dict:
    """Shared by run and report: select, judge, then build the one model.

    The judgment layer runs first and to completion; the report layer only
    reads its results."""
    vector_set = VectorSet.load(args.set)
    contrast_paths = list(args.contrast or [])
    contrast_entries = [load_contrast_vector(path, vector_set) for path in contrast_paths]
    selection = _selection(args)
    ids = select_ids(
        vector_set,
        vector_id=selection["value"] if selection["mode"] == "id" else None,
        vector_class=selection["value"] if selection["mode"] == "class" else None,
    )
    outcomes = run_vector_set(vector_set, ids)
    contrast = [
        (run_contrast(vector_set, str(entry["id"])), contrast_source(path))
        for path, entry in zip(contrast_paths, contrast_entries, strict=True)
        if entry["id"] in ids
    ]
    baseline, baseline_source = (None, None)
    if args.baseline:
        baseline, baseline_source = load_baseline(args.baseline)
    return build_report(
        vector_set,
        args.set,
        outcomes,
        selection=selection,
        clock=clock_from_spec(clock_spec),
        contrast=contrast,
        baseline=baseline,
        baseline_source=baseline_source,
    )


def _cmd_run(args: argparse.Namespace) -> int:
    try:
        # run prints judgments, not a dated report: pin the stamp to the
        # epoch so its output is reproducible (the stamp is not printed).
        model = _build_model(args, "@0")
    except KeyError as exc:
        print(f"aav run: {exc.args[0]}", file=sys.stderr)
        return 2
    if args.json:
        sys.stdout.write(render_json(canonicalize(model)))
    else:
        sys.stdout.write(render_text(model))
    rec = model["reconciliation"]
    if rec is not None:
        return 1 if rec["divergences"] else 0
    return 1 if model["summary"]["mismatched"] else 0


def _cmd_report(args: argparse.Namespace) -> int:
    try:
        model = _build_model(args, args.clock)
    except KeyError as exc:
        print(f"aav report: {exc.args[0]}", file=sys.stderr)
        return 2
    if args.canonical:
        model = canonicalize(model)
    text = render_json(model) if args.format == "json" else render_md(model)
    if args.out:
        Path(args.out).write_bytes(text.encode("utf-8"))
    else:
        sys.stdout.write(text)
    return 0


def _add_selection(parser: argparse.ArgumentParser, *, required: bool) -> None:
    group = parser.add_mutually_exclusive_group(required=required)
    group.add_argument("--all", action="store_true", help="every vector in the set")
    group.add_argument("--id", metavar="VECTOR-ID", help="one vector, by id (e.g. N-09b)")
    group.add_argument(
        "--class",
        dest="vector_class",
        metavar="CLASS",
        help="every vector of one class (positive, negative-message, negative-behavior)",
    )
    parser.add_argument("--set", required=True, help="vectors.json path")
    parser.add_argument(
        "--contrast",
        action="append",
        metavar="FILE",
        help="contrast vector file to run through the contrast engine (repeatable)",
    )
    parser.add_argument("--baseline", metavar="FILE", help="recorded baseline to reconcile with")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="aav",
        description="WIMSE HTTP signature verification core (draft-ietf-wimse-http-signature-09).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    verify_parser = sub.add_parser("verify", help="judge one artifact")
    verify_parser.add_argument("--message", required=True, help="HTTP message file")
    verify_parser.add_argument("--paired", help="paired request file (for responses)")
    verify_parser.add_argument("--config", required=True, help="trusted config JSON file")
    verify_parser.add_argument("--time", required=True, type=int, help="verification time (Unix)")
    verify_parser.add_argument("--json", action="store_true", help="machine-readable output")
    verify_parser.set_defaults(func=_cmd_verify)

    vectors_parser = sub.add_parser("run-vectors", help="run a published vector set")
    vectors_parser.add_argument("--set", required=True, help="vectors.json path")
    vectors_parser.add_argument("--only", nargs="*", help="restrict to these vector ids")
    vectors_parser.add_argument("--json", action="store_true", help="machine-readable output")
    vectors_parser.set_defaults(func=_cmd_run_vectors)

    run_parser = sub.add_parser("run", help="run a selection of a vector set (section 4.2)")
    _add_selection(run_parser, required=True)
    run_parser.add_argument("--json", action="store_true", help="canonical JSON report body")
    run_parser.set_defaults(func=_cmd_run)

    report_parser = sub.add_parser("report", help="render the run report (section 4.3)")
    report_parser.add_argument("--format", required=True, choices=["json", "md"])
    _add_selection(report_parser, required=False)
    report_parser.add_argument(
        "--clock",
        default="system",
        help="timestamp source: system (default), @UNIX seconds, or an ISO 8601 instant",
    )
    report_parser.add_argument(
        "--canonical",
        action="store_true",
        help="omit the volatile meta envelope; byte-identical across runs over the same set",
    )
    report_parser.add_argument("--out", metavar="PATH", help="write here instead of stdout")
    report_parser.set_defaults(func=_cmd_report)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
