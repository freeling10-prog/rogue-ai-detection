"""Gunicorn config for the Zone A container (loaded with ``-c gunicorn.conf.py``).

Only the bind address lives here, because it goes through agent-watch's non-loopback guard:

* default ``127.0.0.1:8000`` (loopback, safe for local runs);
* inside the compose stack ``AGENT_WATCH_BIND=0.0.0.0:8000`` is set TOGETHER WITH
  ``AGENT_WATCH_ALLOW_NONLOCAL=1`` - the explicit equivalent of ``--allow-nonlocal``.  Binding 0.0.0.0 is
  only acceptable because the container sits on a compose network declared ``internal: true`` that nginx
  alone can reach.  Without the explicit opt-in a non-loopback bind aborts startup.

All other flags (workers/threads/timeouts/request limits) are given on the command line in the Dockerfile.
"""
import os

from agentwatch.honeytoken import check_bind

_bind = os.environ.get("AGENT_WATCH_BIND", "127.0.0.1:8000")
_host = _bind.rsplit(":", 1)[0].strip("[]")
check_bind(_host, os.environ.get("AGENT_WATCH_ALLOW_NONLOCAL") == "1")   # SystemExit if not opted in

bind = _bind
accesslog = None          # gunicorn's access log would carry raw query strings; agent-watch scrubs its own logs
errorlog = "-"
loglevel = "warning"
