from pathlib import Path

import pytest

FIX = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture
def fix() -> Path:
    return FIX
