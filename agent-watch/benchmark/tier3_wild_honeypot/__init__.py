"""Tier 3: live nginx/gunicorn honeypot logs (.access.jsonl / .leads.jsonl) pulled from an isolated edge host."""
from .dataset_card import build_card, collect_stats          # noqa: F401
from .validator import Tier3Input, load_slot                 # noqa: F401
