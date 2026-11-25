"""Contrast (multi-evaluation) vectors: N-09b and the section 2.2 table.

A contrast vector runs ONE message through the full judgment chain at two
or more verification moments (design sections 2.5 and 3.4). Each evaluation
carries its own ``verify_time`` and its own complete ``expect``; the runner
runs the full stage chain independently for every evaluation. Stage results
are never shared or cached across evaluations.

The item verdict is ``pass`` if and only if every evaluation's outcome and
primary attribution match its expectation AND no CONTRAST_ANOMALY is raised.

A CONTRAST_ANOMALY is raised when a time-invariant step disagrees between
legs. The signature-verification stages take no time input (the root of
the invariance): the WIT issuer signature (step 1), the WIT cnf binding
(step 1b), signature-input selection, parameter and coverage checks,
signature-base construction, content-digest, message-signature
cryptography (step 2), and audience (step 4). The time-sensitive steps --
WIT expiry (step 1c) and the signature validity window (step 5) -- may
legitimately differ between legs.

The stepwise table (design section 2.2) maps the contrast steps to stages:
steps 1/1b/1c -> WIT (issuer signature / cnf binding / WIT not expired),
step 2 -> CRYPTO, step 3 -> PARAMS + COVERAGE, step 4 -> AUD, step 5 ->
WINDOW.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .httpmsg import parse_message
from .vectors import VectorSet
from .verifier import Judgment
from .wit import wit_steps

CONTRAST_ANOMALY = "CONTRAST_ANOMALY"

#: Steps of the section 2.2 table, in order: (step, label, time-invariant).
STEP_DEFS: tuple[tuple[str, str, bool], ...] = (
    ("1", "WIT issuer signature", True),
    ("1b", "WIT cnf binding", True),
    ("1c", "WIT not expired", False),
    ("2", "Message signature cryptography", True),
    ("3", "Coverage and required parameters", True),
    ("4", "wimse-aud match", True),
    ("5", "Signature validity window", False),
)

#: Time-invariant stages compared across legs beyond the stepwise table.
INVARIANT_STAGES: tuple[str, ...] = ("SELECT", "BASE", "DIGEST")

#: Invariant steps of the stepwise table (step 1c and step 5 take time).
INVARIANT_STEPS: tuple[str, ...] = ("1", "1b", "2", "3", "4")


@dataclass
class LegStep:
    """One contrast step's outcome for one leg."""

    step: str
    label: str
    status: str  # "pass" | "fail" | "skip" | "blocked"
    code: str | None


@dataclass
class LegResult:
    """One evaluation (leg) of a contrast vector, run independently."""

    verify_time: int
    judgment: Judgment
    expect: dict[str, Any]
    match: bool
    mismatches: list[str] = field(default_factory=list)
    steps: dict[str, LegStep] = field(default_factory=dict)
    invariant_stages: dict[str, str] = field(default_factory=dict)


@dataclass
class ContrastRow:
    """One row of the stepwise contrast table (design section 2.2)."""

    step: str
    label: str
    invariant: bool
    statuses: list[str]
    codes: list[str | None]


@dataclass
class ContrastResult:
    """The outcome of running one contrast vector."""

    vector_id: str
    verdict: str  # "pass" | "fail"
    legs: list[LegResult] = field(default_factory=list)
    table: list[ContrastRow] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)
    detail: str = ""


def _stage_status(judgment: Judgment, name: str) -> str:
    """The status of one judgment stage, or "skip" when it did not run."""
    result = judgment.stage(name)
    return result.status if result is not None else "skip"


def _stage_code(judgment: Judgment, name: str) -> str | None:
    """The failing code of one judgment stage, if any."""
    result = judgment.stage(name)
    return result.code if result is not None else None


def _wit_header(message_raw: str) -> str | None:
    """The Workload-Identity-Token header of a message, if present."""
    message = parse_message(message_raw)
    for name, value in message.headers:
        if name == "workload-identity-token":
            return value
    return None


def _leg_steps(
    verifier: Any, message_raw: str, verify_time: int, judgment: Judgment
) -> dict[str, LegStep]:
    """Build the section 2.2 steps for one leg from its judgment."""
    steps: dict[str, LegStep] = {}
    wit_header = _wit_header(message_raw)
    if wit_header is None:
        for step_id, label, _ in STEP_DEFS[:3]:
            steps[step_id] = LegStep(step=step_id, label=label, status="skip", code=None)
    else:
        for wit_step in wit_steps(wit_header, verifier.config.issuer_anchor_jwk, verify_time):
            steps[wit_step.step] = LegStep(
                step=wit_step.step, label=wit_step.label, status=wit_step.status, code=wit_step.code
            )
    steps["2"] = LegStep(
        step="2",
        label="Message signature cryptography",
        status=_stage_status(judgment, "CRYPTO"),
        code=_stage_code(judgment, "CRYPTO"),
    )
    params = _stage_status(judgment, "PARAMS")
    coverage = _stage_status(judgment, "COVERAGE")
    if "fail" in (params, coverage):
        status3 = "fail"
    elif "skip" in (params, coverage):
        status3 = "skip"
    elif "blocked" in (params, coverage):
        status3 = "blocked"
    else:
        status3 = "pass"
    code3 = (
        _stage_code(judgment, "PARAMS") if params == "fail" else _stage_code(judgment, "COVERAGE")
    )
    steps["3"] = LegStep(
        step="3", label="Coverage and required parameters", status=status3, code=code3
    )
    steps["4"] = LegStep(
        step="4",
        label="wimse-aud match",
        status=_stage_status(judgment, "AUD"),
        code=_stage_code(judgment, "AUD"),
    )
    steps["5"] = LegStep(
        step="5",
        label="Signature validity window",
        status=_stage_status(judgment, "WINDOW"),
        code=_stage_code(judgment, "WINDOW"),
    )
    return steps


def _http_status(judgment: Judgment) -> int | None:
    """The HTTP status for a judgment (the suite's mapping: REJECT -> 400)."""
    if judgment.verdict == "REJECT":
        return 400
    return None


def _problem_type(judgment: Judgment) -> str | None:
    """The problem type for a judgment (REJECT -> wimse-signature-invalid)."""
    if judgment.verdict == "REJECT":
        return "wimse-signature-invalid"
    return None


def _check_expectation(judgment: Judgment, expect: dict[str, Any]) -> list[str]:
    """Compare a leg's judgment with its full expectation; list mismatches."""
    mismatches: list[str] = []
    if judgment.verdict != expect.get("outcome"):
        mismatches.append(f"outcome: expected {expect.get('outcome')}, got {judgment.verdict}")
    if "failing_stage" in expect and judgment.failing_stage != expect["failing_stage"]:
        mismatches.append(
            f"failing_stage: expected {expect['failing_stage']}, got {judgment.failing_stage}"
        )
    if "failing_code" in expect and judgment.failing_code != expect["failing_code"]:
        mismatches.append(
            f"failing_code: expected {expect['failing_code']}, got {judgment.failing_code}"
        )
    if "cascades" in expect and list(judgment.cascades) != list(expect["cascades"]):
        mismatches.append(f"cascades: expected {expect['cascades']}, got {list(judgment.cascades)}")
    if "http_status" in expect and _http_status(judgment) != expect["http_status"]:
        mismatches.append(
            f"http_status: expected {expect['http_status']}, got {_http_status(judgment)}"
        )
    if "problem_type" in expect and _problem_type(judgment) != expect["problem_type"]:
        mismatches.append(
            f"problem_type: expected {expect['problem_type']}, got {_problem_type(judgment)}"
        )
    return mismatches


def check_anomalies(legs: list[LegResult]) -> list[str]:
    """Flag time-invariant steps that disagree between legs.

    Only the invariant steps are compared: the time-sensitive steps
    (1c WIT expiry, 5 signature window) may legitimately differ. A
    difference in an invariant step's recorded status -- pass in one leg,
    fail or skip in another -- is a CONTRAST_ANOMALY: a time change alone
    cannot change the outcome of a step that takes no time input, so the
    legs were not run as the same message through the same chain.
    """
    anomalies: list[str] = []
    if len(legs) < 2:
        return anomalies
    labels = {step: label for step, label, _ in STEP_DEFS}
    for step_id in INVARIANT_STEPS:
        statuses = [leg.steps[step_id].status for leg in legs]
        if len(set(statuses)) > 1:
            per_leg = ", ".join(f"t={leg.verify_time}:{leg.steps[step_id].status}" for leg in legs)
            anomalies.append(
                f"{CONTRAST_ANOMALY}: step {step_id} ({labels[step_id]}) "
                f"differs across legs: {per_leg}"
            )
    for stage in INVARIANT_STAGES:
        statuses = [leg.invariant_stages[stage] for leg in legs]
        if len(set(statuses)) > 1:
            per_leg = ", ".join(
                f"t={leg.verify_time}:{leg.invariant_stages[stage]}" for leg in legs
            )
            anomalies.append(f"{CONTRAST_ANOMALY}: stage {stage} differs across legs: {per_leg}")
    return anomalies


def _build_table(legs: list[LegResult]) -> list[ContrastRow]:
    """Build the stepwise contrast table (design section 2.2)."""
    rows: list[ContrastRow] = []
    for step_id, label, invariant in STEP_DEFS:
        rows.append(
            ContrastRow(
                step=step_id,
                label=label,
                invariant=invariant,
                statuses=[leg.steps[step_id].status for leg in legs],
                codes=[leg.steps[step_id].code for leg in legs],
            )
        )
    rows.append(
        ContrastRow(
            step="final",
            label="Final judgment",
            invariant=False,
            statuses=[leg.judgment.verdict for leg in legs],
            codes=[leg.judgment.failing_code for leg in legs],
        )
    )
    return rows


def run_contrast(
    vector_set: VectorSet, vector_id: str, *, evaluations: list[dict[str, Any]] | None = None
) -> ContrastResult:
    """Run one contrast vector: each evaluation through the full chain.

    Every evaluation is run independently with ``verifier.verify``; the
    verifier builds a fresh stage chain per call, so no stage result is
    shared or cached across evaluations. The verdict is ``pass`` only when
    every evaluation matches its expectation and no CONTRAST_ANOMALY is
    raised.
    """
    entry = vector_set.vectors[vector_id]
    if entry.get("mode") != "contrast":
        raise ValueError(
            f"vector {vector_id} is not a contrast vector (mode={entry.get('mode')!r})"
        )
    evals = evaluations if evaluations is not None else entry.get("evaluations", [])
    if len(evals) < 2:
        raise ValueError(f"contrast vector {vector_id} needs at least two evaluations")
    artifact = vector_set.construct(vector_id)
    verifier = vector_set.make_verifier()
    legs: list[LegResult] = []
    for evaluation in evals:
        verify_time = int(evaluation["verify_time"])
        judgment = verifier.verify(
            artifact.message_raw, verify_time, artifact.paired_raw, artifact.expected_bases
        )
        expect = dict(evaluation.get("expect", {}))
        mismatches = _check_expectation(judgment, expect)
        legs.append(
            LegResult(
                verify_time=verify_time,
                judgment=judgment,
                expect=expect,
                match=not mismatches,
                mismatches=mismatches,
                steps=_leg_steps(verifier, artifact.message_raw, verify_time, judgment),
                invariant_stages={name: _stage_status(judgment, name) for name in INVARIANT_STAGES},
            )
        )
    anomalies = check_anomalies(legs)
    verdict = "pass" if all(leg.match for leg in legs) and not anomalies else "fail"
    leg_summary = "; ".join(
        f"t={leg.verify_time}: {leg.judgment.verdict}"
        + ("" if leg.match else f" (mismatch: {'; '.join(leg.mismatches)})")
        for leg in legs
    )
    detail = f"{vector_id}: {verdict} ({leg_summary})"
    if anomalies:
        detail += f"; anomalies: {'; '.join(anomalies)}"
    return ContrastResult(
        vector_id=vector_id,
        verdict=verdict,
        legs=legs,
        table=_build_table(legs),
        anomalies=anomalies,
        detail=detail,
    )


def load_contrast_vector(path: str | Path, vector_set: VectorSet) -> dict[str, Any]:
    """Load one contrast vector entry from a file into a vector set.

    The file holds a single vector entry (the ``vectors/v4/`` layout).
    The entry is registered in the set by id, replacing any entry with
    the same id, so its base vector resolves from the set.
    """
    with open(path, encoding="utf-8") as handle:
        entry = json.load(handle)
    if not isinstance(entry, dict) or "id" not in entry:
        raise ValueError(f"{path} does not contain a vector entry")
    if entry.get("mode") != "contrast":
        raise ValueError(f"vector {entry.get('id')} in {path} is not a contrast vector")
    vector_set.add_entry(entry)
    return entry


def run_contrast_from_file(path: str | Path, vector_set: VectorSet) -> ContrastResult:
    """Load a contrast vector from a file and run it."""
    entry = load_contrast_vector(path, vector_set)
    return run_contrast(vector_set, str(entry["id"]))
