"""Benchmark toolkit: three strictly separated trace tiers (see docs/benchmark-protocol.md).

tier1_synthetic_regression  same-author synthetic data: a REGRESSION CHECK, never a benchmark.
tier2_local_real_llm        real local red-team traces (Ollama/API agents, headless browsers on 127.0.0.1): EMPTY until you capture some.
tier3_wild_honeypot         live traffic from an isolated edge honeypot: EMPTY until you pull some.

Metrics from different tiers are NEVER merged into one number.  Nothing in this package opens a network connection.
"""
from __future__ import annotations

MANIFEST_SCHEMA = "agentwatch.benchmark.manifest/1"
TOOLKIT_VERSION = "1"

TIER1 = "tier1_synthetic_regression"
TIER2 = "tier2_local_real_llm"
TIER3 = "tier3_wild_honeypot"
TIERS = (TIER1, TIER2, TIER3)

NOT_COMPARABLE_NOTE = (
    "NOT COMPARABLE: tier1 (same-author synthetic regression), tier2 (real local LLM red-team traces) and tier3 (wild honeypot "
    "traffic) measure different things on differently-generated data. Their metrics are listed separately and are never averaged, "
    "pooled, ranked against each other, or merged into one score. A tier1 number says nothing about real-world detection."
)
