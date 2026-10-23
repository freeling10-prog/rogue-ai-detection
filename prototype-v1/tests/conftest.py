import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rogue_detect.pipeline import analyze  # noqa: E402
from rogue_detect.synthetic import generate  # noqa: E402


@pytest.fixture(scope="session")
def dataset():
    events, roles = generate(7)
    return events, roles


@pytest.fixture(scope="session")
def analysis(dataset):
    return analyze(dataset[0])
