from __future__ import annotations

import pytest

from benchmarks.wild_mcp_corpus import score as S


@pytest.fixture
def pr40_classifier():
    """Tests that recompute the committed PR #40 artifacts score with the classifier that made them."""
    with S.classifier("pr40"):
        yield
