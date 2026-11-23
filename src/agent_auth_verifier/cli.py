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

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
