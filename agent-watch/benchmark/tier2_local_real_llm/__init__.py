"""Tier 2: real local red-team traces (redteam/llm_agent.py with Ollama/API, or headless browsers) against a 127.0.0.1 honeypot."""
from .scorer import aggregate, score_run                     # noqa: F401
from .validator import RunResult, validate_run_dir, validate_slot   # noqa: F401
