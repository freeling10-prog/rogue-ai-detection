"""Console / process log hygiene: nothing that reaches stdout or stderr may carry raw query strings or secrets.

Why this exists
---------------
The lead log, registry, reports and exports have always been scrubbed (``scrubber.py``).  A live demo found that the
Flask/werkzeug *development server* still printed its own access log to the console with the raw request line,
including query strings (``?api_key=sk-...&contact=jane@example.com``) and the coordination-board ``token=``/``nonce=``
values.  Every other sink had the same potential problem: werkzeug error lines (``code 400, message Bad request
syntax ('GET /?... HTTP/1.1')``), gunicorn's error log ("Invalid request line"), Flask's own logger, tracebacks.

Policy (applied to *every* log record, whichever logger emitted it):

1. percent-decode, then run the salted-hash secret scrubber (``sk-...``, ``ghp_...``, ``AKIA...``, e-mails, bearer tokens);
2. **drop query strings entirely** (``?[query-redacted]``): they are the one attacker-controlled free-text field of a
   request line and the usual home of tokens, so suppressing beats pattern matching;
3. mask the honeypot's own decoy keys / passwords / canary phrases / session canaries and long opaque path segments
   (server-issued cursor tokens such as ``/api/v2/dump/page/<token>``).

What it does not do: it does not touch the scrubbed JSONL files (already scrubbed at write time), and it cannot protect
output of third-party code that bypasses ``logging`` and ``WSGIRequestHandler.log`` (for example something that prints to
stderr directly).  ``tests/test_console_logs.py`` starts real servers and greps captured stdout/stderr.
"""
from __future__ import annotations

import logging
import re
import traceback
from typing import Any, Optional
from urllib.parse import unquote

from .scrubber import get_default_scrubber

_QUERY = re.compile(r"\?[^\s\"']*")
_DECOY = re.compile(r"AWFAKE-DO-NOT-USE-[A-Za-z0-9]+|NOT-A-REAL-PASSWORD-[A-Za-z0-9]+|AWCANARY-[A-Za-z0-9-]+|sc-[0-9a-f]{10}")
_LONG_SEG = re.compile(r"(?<=/)(?:[0-9a-fA-F]{10,}|[A-Za-z0-9_\-]{20,})(?=[/\s\"'?]|$)")
_HANDLED = "_agentwatch_safe"


def safe_text(text: Any) -> str:
    """Return *text* with secrets scrubbed, query strings suppressed and opaque ids masked."""
    raw = text if isinstance(text, str) else str(text)
    try:
        scrubber = get_default_scrubber()
        out = scrubber.scrub_text(unquote(raw))
        out = _DECOY.sub("[REDACTED_DECOY_TOKEN]", out)
        out = _QUERY.sub("?[query-redacted]", out)
        out = _LONG_SEG.sub("[id]", out)
        return out
    except Exception:                                    # noqa: BLE001 - never let logging hygiene leak by failing open
        return "[log message suppressed: scrub failure]"


class SafeLogFilter(logging.Filter):
    """Rewrite each record in place so every handler downstream only ever sees the safe text."""

    def filter(self, record: logging.LogRecord) -> bool:
        if getattr(record, _HANDLED, False):
            return True
        try:
            msg = record.getMessage()
        except Exception:                                # noqa: BLE001
            msg = str(record.msg)
        record.msg, record.args = safe_text(msg), ()
        if record.exc_info:
            record.exc_text = safe_text("".join(traceback.format_exception(*record.exc_info)))
            record.exc_info = None
        elif record.exc_text:
            record.exc_text = safe_text(record.exc_text)
        if record.stack_info:
            record.stack_info = safe_text(record.stack_info)
        setattr(record, _HANDLED, True)
        return True


_FILTER = SafeLogFilter()
LOGGER_NAMES = ("werkzeug", "flask.app", "gunicorn.error", "gunicorn.access", "agentwatch")


def install_safe_logging() -> None:
    """Attach the filter to every logger that can reach a console, and to the root logger's handlers.

    Idempotent.  Filters on a *logger* only see records created by that logger, so the handlers of the root logger are
    covered as well (records propagated from third-party child loggers)."""
    for name in LOGGER_NAMES:
        lg = logging.getLogger(name)
        if _FILTER not in lg.filters:
            lg.addFilter(_FILTER)
        for h in lg.handlers:
            if _FILTER not in h.filters:
                h.addFilter(_FILTER)
    for h in logging.getLogger().handlers:
        if _FILTER not in h.filters:
            h.addFilter(_FILTER)


def make_request_handler() -> Any:
    """werkzeug request handler whose console log goes through :func:`safe_text` (dev server only)."""
    from werkzeug.serving import WSGIRequestHandler

    class SafeRequestHandler(WSGIRequestHandler):
        def log(self, type: str, message: str, *args: Any) -> None:                 # noqa: A002 - werkzeug's signature
            try:
                text = message % args if args else message
            except (TypeError, ValueError):
                text = f"{message} {args}"
            super().log(type, "%s", safe_text(text).replace("%", "%%"))

        def log_request(self, code: Any = "-", size: Any = "-") -> None:
            # Never format self.path (query included); log method, query-free path and status only.
            path = (getattr(self, "path", "") or "").split("?", 1)[0]
            self.log("info", '"%s %s %s" %s %s', getattr(self, "command", "-"), path,
                     getattr(self, "request_version", "-"), code, size)

    return SafeRequestHandler


def make_gunicorn_logger_class() -> Optional[type]:
    """gunicorn logger class that scrubs every message (set ``logger_class`` in the gunicorn config)."""
    try:
        from gunicorn.glogging import Logger
    except ImportError:
        return None

    class SafeGunicornLogger(Logger):                                              # type: ignore[misc]
        def setup(self, cfg: Any) -> None:
            super().setup(cfg)
            for lg in (self.error_log, self.access_log):
                if _FILTER not in lg.filters:
                    lg.addFilter(_FILTER)
                for h in lg.handlers:
                    if _FILTER not in h.filters:
                        h.addFilter(_FILTER)

        def access(self, resp: Any, req: Any, environ: Any, request_time: Any) -> None:
            return None                      # access log is disabled by design: it would carry raw query strings

    return SafeGunicornLogger


SafeGunicornLogger = make_gunicorn_logger_class()      # None when gunicorn is not installed; referenced by gunicorn.conf.py
