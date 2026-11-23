"""The published suite v4, run end to end through the verifier.

Every judged message/contrast vector must reproduce its published
expectation: the layer-1 verdict and, for rejections, the layer-2 failing
stage and code. Two documented exceptions, both analyzed in selfcheck.md:

* N-09 -- divergence in primary-stage attribution only. At its verify
  time (T0+3600), WIT-A is also expired (its exp is exactly T0+3600), a
  confound the suite's own anchor for N-09 records ("at that time WIT-A
  is also expired; attribution isolation is weak; the decision rule
  judges only the time window"). This verifier validates the WIT first,
  as the draft mandates, so it attributes the failure to WIT and reports
  WINDOW as a cascade. The verdict (REJECT) agrees, and at T0+1800 --
  WIT still valid, signature window closed -- the same artifact is
  attributed to WINDOW exactly as published (see the dedicated test).

* The six behavior probes (N-16..N-20, N-22) carry no artifact; an
  artifact verifier cannot judge implementation behavior, so they are
  reported NOT_JUDGEABLE rather than passed or failed.
"""

import pytest

from agent_auth_verifier.vectors import VectorSet, run_vector_set

PROBES = ["N-16", "N-17", "N-18", "N-19", "N-20", "N-22"]


@pytest.fixture(scope="module")
def outcomes(vector_set: VectorSet) -> dict:
    return {o.vector_id: o for o in run_vector_set(vector_set)}


def test_set_shape(vector_set: VectorSet) -> None:
    assert vector_set.set_version == "v4"
    assert vector_set.draft_version == "draft-ietf-wimse-http-signature-08"
    assert len(vector_set.vectors) == 29
    assert len(vector_set.observations) == 3


def test_all_judged_vectors_match_except_documented_n09(outcomes: dict) -> None:
    mismatches = [
        vector_id for vector_id, outcome in outcomes.items() if outcome.status == "MISMATCH"
    ]
    assert mismatches == ["N-09"]


@pytest.mark.parametrize("probe", PROBES)
def test_probes_are_not_judgeable(outcomes: dict, probe: str) -> None:
    assert outcomes[probe].status == "NOT_JUDGEABLE"


def test_n09_documented_divergence(vector_set: VectorSet, outcomes: dict) -> None:
    outcome = outcomes["N-09"]
    assert outcome.status == "MISMATCH"
    (evaluation,) = outcome.evaluations
    actual = evaluation["actual"]
    assert actual["verdict"] == "REJECT"
    assert actual["failing_stage"] == "WIT"
    assert actual["failing_code"] == "E_WIT_EXPIRED"
    assert actual["cascades"] == ["WINDOW"]


def test_window_attribution_when_wit_still_valid(vector_set) -> None:
    """Same artifact as N-09 at T0+1800: the signature window has closed
    but WIT-A is still valid, so the failure is attributed to WINDOW,
    matching the published N-09/N-09b expectation shape."""
    verifier = vector_set.make_verifier()
    artifact = vector_set.construct("N-09")
    judgment = verifier.verify(artifact.message_raw, 1795001800)
    assert judgment.verdict == "REJECT"
    assert judgment.failing_stage == "WINDOW"
    assert judgment.failing_code == "E_WINDOW_OUTSIDE"


def test_selection_is_by_tag_not_label(vector_set) -> None:
    """Behavioral evidence relevant to probe N-22: on P-06 this verifier
    selects sig2 (the tag match), not sig1 (the first label)."""
    verifier = vector_set.make_verifier()
    artifact = vector_set.construct("P-06")
    judgment = verifier.verify(artifact.message_raw, 1795000060)
    assert judgment.verdict == "ACCEPT"
    assert judgment.selected_label == "sig2"
