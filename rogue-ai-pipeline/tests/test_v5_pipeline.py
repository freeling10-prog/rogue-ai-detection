"""v5 pipeline: the collector's harness label is carried (descriptively, never scored) into leads and into the STIX 2.1 indicator
extension, and the pinned OASIS validator still passes.  Same-author synthetic data."""
from __future__ import annotations

import json
from typing import Any, Dict

import pytest
from pydantic import ValidationError

from rogue_pipeline.config import Config, Policy
from rogue_pipeline.pipeline import Pipeline
from rogue_pipeline.pseudonymize import Pseudonymizer
from rogue_pipeline.schema import RawEvent
from rogue_pipeline.stix_export import build_bundle, validate_bundle

from test_v4_pipeline import BOT_B, G, KEY, QUIET_B, run


def _with_harness(g: G, arche: str, conf: str) -> list[Dict[str, Any]]:
    for e in g.events:
        e["web"]["harness_archetype"], e["web"]["harness_confidence"] = arche, conf
    return g.events


def _webdriver_client(arche: str = "headless_or_http_mimic", conf: str = "high"):
    g = G("192.0.2.61").pages(4, assets=("a.css", "a.js"), beacon=BOT_B)
    return _with_harness(g, arche, conf)


def test_harness_label_reaches_the_lead_and_never_changes_the_score():
    labelled, _ = run(_webdriver_client())
    plain_g = G("192.0.2.61").pages(4, assets=("a.css", "a.js"), beacon=BOT_B)
    plain, _ = run(plain_g.events)
    assert labelled.leads and plain.leads
    assert labelled.leads[0].harness == {"archetype": "headless_or_http_mimic", "confidence": "high"}
    assert plain.leads[0].harness is None
    assert labelled.leads[0].score == plain.leads[0].score            # descriptive only: identical fused score
    assert labelled.leads[0].to_dict()["harness"]["archetype"] == "headless_or_http_mimic"


def test_unclassified_label_is_not_attached():
    res, _ = run(_webdriver_client("unclassified", "low"))
    assert res.leads and res.leads[0].harness is None


def test_schema_rejects_an_invented_archetype():
    ev = _webdriver_client()[0]
    ev["web"]["harness_archetype"] = "totally_made_up"
    with pytest.raises(ValidationError):
        RawEvent.model_validate(ev)
    ev["web"]["harness_archetype"] = "mcp_tool_runner"
    ev["web"]["harness_confidence"] = "certain"
    with pytest.raises(ValidationError):
        RawEvent.model_validate(ev)


def test_stix_indicator_carries_harness_extension_and_still_validates():
    res, _ = run(_webdriver_client())
    leads = [l.to_dict() for l in res.leads]
    bundle = build_bundle(leads, [l["lead_id"] for l in leads])
    text = bundle.serialize(pretty=True)
    v = validate_bundle(text)
    assert v.parsed_ok, v.parse_error
    assert v.validator_available and v.validator_ok, v.validator_messages
    ind = [o for o in json.loads(text)["objects"] if o["type"] == "indicator" and "x_harness_archetype" in o]
    assert ind and ind[0]["x_harness_archetype"]["archetype"] == "headless_or_http_mimic"
    assert "descriptive" in ind[0]["x_harness_archetype"]["note"]
    assert "headless_or_http_mimic" not in ind[0]["description"]          # never in free-text fields
