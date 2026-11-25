"""agent-auth-verifier: verification core for WIMSE workload-to-workload
HTTP message signatures (draft-ietf-wimse-http-signature-09).

Library and CLI producing two-layer judgments (artifact verdict plus
twelve-stage failure classification) aligned with the WIMSE HTTP signature
test vector suite. Verification core only: no token issuance, no
conformance mode, no network access at runtime.
"""

from .contrast import (
    CONTRAST_ANOMALY,
    ContrastResult,
    ContrastRow,
    LegResult,
    LegStep,
    check_anomalies,
    load_contrast_vector,
    run_contrast,
    run_contrast_from_file,
)
from .vectors import VectorOutcome, VectorSet, run_vector_set
from .verifier import Judgment, KnownKey, StageResult, TrustedConfig, Verifier

__version__ = "0.1.0"

__all__ = [
    "CONTRAST_ANOMALY",
    "ContrastResult",
    "ContrastRow",
    "Judgment",
    "KnownKey",
    "LegResult",
    "LegStep",
    "StageResult",
    "TrustedConfig",
    "VectorOutcome",
    "VectorSet",
    "Verifier",
    "check_anomalies",
    "load_contrast_vector",
    "run_contrast",
    "run_contrast_from_file",
    "run_vector_set",
]
