"""agent-auth-verifier: verification core for WIMSE workload-to-workload
HTTP message signatures (draft-ietf-wimse-http-signature-09).

Library and CLI producing two-layer judgments (artifact verdict plus
twelve-stage failure classification) aligned with the WIMSE HTTP signature
test vector suite. Verification core only: no token issuance, no
conformance mode, no network access at runtime.
"""

from .vectors import VectorOutcome, VectorSet, run_vector_set
from .verifier import Judgment, KnownKey, StageResult, TrustedConfig, Verifier

__version__ = "0.1.0"

__all__ = [
    "Judgment",
    "KnownKey",
    "StageResult",
    "TrustedConfig",
    "VectorOutcome",
    "VectorSet",
    "Verifier",
    "__version__",
    "run_vector_set",
]
