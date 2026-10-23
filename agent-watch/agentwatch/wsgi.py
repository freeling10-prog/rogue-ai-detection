"""WSGI entry point for gunicorn (Zone A container):  ``gunicorn agentwatch.wsgi:app``.

Configuration comes only from environment variables (nothing is read from the request):

* ``AGENT_WATCH_LOG``          lead JSONL path           (default /data/leads.jsonl)
* ``AGENT_WATCH_STATE``        sqlite state path         (default /data/state.sqlite)
* ``AGENT_WATCH_REGISTRY``     decoy registry JSON path  (default /data/registry.json)
* ``AGENT_WATCH_SEED``         token seed; default: random, persisted 0600 in ``AGENT_WATCH_SEED_FILE`` so that
                               all gunicorn workers serve the SAME decoys
* ``AGENT_WATCH_BEHIND_PROXY`` ``1`` => trust exactly one reverse-proxy hop (ProxyFix); default off
* ``AGENT_WATCH_SCRUB_SALT`` / ``AGENT_WATCH_SALT_FILE``  scrubber salt (see scrubber.py)
* ``AGENT_WATCH_TARPIT_S`` / ``AGENT_WATCH_TARPIT_MAX_S``  optional capped tarpit

This module never binds a socket itself, so ``check_bind`` is not involved; the *container* binds
0.0.0.0 on an internal-only compose network (see deploy/README section in the main README).
"""
from __future__ import annotations

import os
from pathlib import Path

from .honeypot import create_honeypot_app
from .scrubber import load_or_create_salt

DATA = os.environ.get("AGENT_WATCH_DATA", "/data")


def _seed() -> str:
    """Token-id seed shared by every gunicorn worker (else each worker would invent different decoys)."""
    env = os.environ.get("AGENT_WATCH_SEED")
    if env:
        return env
    return load_or_create_salt(Path(os.environ.get("AGENT_WATCH_SEED_FILE", f"{DATA}/registry.seed")))


def build() -> "object":
    return create_honeypot_app(
        os.environ.get("AGENT_WATCH_LOG", f"{DATA}/leads.jsonl"),
        seed=_seed(),
        registry_path=os.environ.get("AGENT_WATCH_REGISTRY", f"{DATA}/registry.json"),
        state_path=os.environ.get("AGENT_WATCH_STATE", f"{DATA}/state.sqlite"),
        tarpit_s=float(os.environ.get("AGENT_WATCH_TARPIT_S", "0")),
        tarpit_max_s=float(os.environ.get("AGENT_WATCH_TARPIT_MAX_S", "5")),
        behind_proxy=os.environ.get("AGENT_WATCH_BEHIND_PROXY") == "1",
        trust_forwarded_for=False,        # the test hook is never enabled from the environment
    )


app = build() if os.environ.get("AGENT_WATCH_WSGI_LAZY") != "1" else None  # type: ignore[assignment]
