from pathlib import Path

import pytest

from agent_auth_verifier.vectors import VectorSet

FIXTURE = Path(__file__).parent / "fixtures" / "vectors.json"


@pytest.fixture(scope="session")
def vector_set() -> VectorSet:
    return VectorSet.load(FIXTURE)


@pytest.fixture(scope="session")
def verifier(vector_set: VectorSet):
    return vector_set.make_verifier()
