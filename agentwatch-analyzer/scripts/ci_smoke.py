"""Offline analyzer smoke for CI.

Reads an archived Tier-2 access log (or the agentlike nginx fixture if that
archive is absent). Does not start a honeypot, bind a port, or open a socket.
Writes findings.json, replay.html, and a STIX 2.1 bundle, then checks the
bundle with the pinned validator.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agentwatch_analyzer.cli import main as analyzer_main
from agentwatch_analyzer.stix_bundle import validate_bundle

ROOT = Path(__file__).resolve().parents[2]
ARCHIVE = (
    ROOT
    / "agent-watch"
    / "benchmark"
    / "tier2_local_real_llm"
    / "slot"
    / "t2-pw_crawler_headless-crawler-s100"
    / "access.jsonl"
)
FIXTURE = ROOT / "agentwatch-analyzer" / "tests" / "fixtures" / "agentlike_nginx.log"


def _choose(explicit: Path | None) -> tuple[Path, str]:
    if explicit is not None:
        fmt = "nginx" if explicit.suffix == ".log" else "json"
        return explicit, fmt
    if ARCHIVE.is_file():
        return ARCHIVE, "json"
    return FIXTURE, "nginx"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline agentwatch-analyzer smoke (no honeypot, no egress)")
    parser.add_argument("--out-dir", type=Path, default=Path("analyzer-smoke"))
    parser.add_argument("--log", type=Path, default=None, help="Access log. Default: archived Tier-2 crawler, else the agentlike fixture")
    args = parser.parse_args(argv)

    log_path, fmt = _choose(args.log)
    if not log_path.is_file():
        print(f"error: log not found: {log_path}", file=sys.stderr)
        return 2

    out = args.out_dir
    rc = analyzer_main([str(log_path), "--format", fmt, "--out-dir", str(out)])
    if rc != 0:
        print(f"error: analyzer exited {rc}", file=sys.stderr)
        return rc

    findings_path = out / "findings.json"
    replay_path = out / "replay.html"
    bundle_path = out / "stix-bundle.json"
    missing = [str(p) for p in (findings_path, replay_path, bundle_path) if not p.is_file()]
    if missing:
        print("error: smoke outputs missing: " + ", ".join(missing), file=sys.stderr)
        return 2

    findings = json.loads(findings_path.read_text(encoding="utf-8"))
    n_findings = len(findings.get("findings") or [])
    if n_findings < 1:
        print(f"error: {log_path} produced no findings", file=sys.stderr)
        return 2
    html = replay_path.read_text(encoding="utf-8")
    if "Content-Security-Policy" not in html:
        print("error: replay.html has no content security policy", file=sys.stderr)
        return 2

    bundle = bundle_path.read_text(encoding="utf-8")
    summary = validate_bundle(bundle)
    (out / "stix-validation.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    if summary.get("parsed_ok") is not True or summary.get("validator_ok") is not True:
        print(json.dumps(summary, indent=2), file=sys.stderr)
        print("error: STIX 2.1 bundle did not validate", file=sys.stderr)
        return 2

    print(json.dumps({
        "log": str(log_path),
        "format": fmt,
        "findings": n_findings,
        "replay_html": str(replay_path),
        "stix_objects": summary.get("object_count"),
        "validator_ok": True,
        "out_dir": str(out),
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
