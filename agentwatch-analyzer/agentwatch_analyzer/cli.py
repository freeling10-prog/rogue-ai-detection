"""CLI: agentwatch-analyzer access.log [--format ...] [--sitemap ...] [--out-dir DIR]

Offline only: never starts a honeypot, never binds a port, never makes outbound calls.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .detect import OFFLINE_MATRIX, analyze_sessions, findings_to_json, na_findings
from .linkgraph import load_sitemap_paths
from .parse import event_to_dict, iter_events
from .prefilter import partition
from .replay import build_replay_html
from .scrub import scrub_obj, scrub_json_line
from .stix_bundle import build_bundle


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="agentwatch-analyzer",
        description="Offline static web-log analyzer (R8–R14 partial). No honeypot, no bind, no egress.",
    )
    p.add_argument("access_log", type=Path, help="Path to access log (nginx/caddy/cloudflare/json)")
    p.add_argument("--format", choices=["auto", "nginx", "caddy", "cloudflare", "json"], default="auto")
    p.add_argument("--sitemap", type=Path, default=None, help="Optional sitemap.xml to strengthen R9 link-graph")
    p.add_argument("--out-dir", type=Path, default=Path("analyzer-out"))
    p.add_argument("--no-stix", action="store_true")
    p.add_argument("--no-replay", action="store_true")
    args = p.parse_args(argv)

    if not args.access_log.is_file():
        print(f"error: log not found: {args.access_log}", file=sys.stderr)
        return 2

    out_dir: Path = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    events = list(iter_events(args.access_log, fmt=args.format))
    sitemap_paths = load_sitemap_paths(args.sitemap) if args.sitemap and args.sitemap.is_file() else None
    kept, filtered = partition(events)

    # 1) scrubbed events JSONL
    events_path = out_dir / "events.scrubbed.jsonl"
    with events_path.open("w", encoding="utf-8") as fh:
        for ev in events:
            fh.write(scrub_json_line(event_to_dict(ev)) + "\n")

    # 2) findings
    findings = analyze_sessions(kept, sitemap_paths=sitemap_paths)
    findings_doc = {
        "schema": "agentwatch-analyzer.findings/1",
        "source_log": str(args.access_log),
        "n_events": len(events),
        "n_sessions_kept": len(kept),
        "n_prefiltered": len(filtered),
        "prefiltered": scrub_obj(filtered),
        "offline_matrix": OFFLINE_MATRIX,
        "honeypot_only_notes": na_findings(),
        "findings": scrub_obj(findings_to_json(findings)),
    }
    findings_path = out_dir / "findings.json"
    findings_path.write_text(json.dumps(findings_doc, indent=2) + "\n", encoding="utf-8")
    leads_path = out_dir / "leads.jsonl"
    with leads_path.open("w", encoding="utf-8") as fh:
        for f in findings_to_json(findings):
            fh.write(json.dumps(scrub_obj(f), ensure_ascii=False) + "\n")

    # 3) replay HTML
    if not args.no_replay:
        html = build_replay_html(kept, findings_to_json(findings))
        (out_dir / "replay.html").write_text(html, encoding="utf-8")

    # 4) STIX
    stix_summary = None
    if not args.no_stix and findings:
        bundle_json, stix_summary = build_bundle(findings_to_json(findings))
        (out_dir / "stix-bundle.json").write_text(bundle_json + "\n", encoding="utf-8")
        (out_dir / "stix-validation.json").write_text(json.dumps(stix_summary, indent=2) + "\n", encoding="utf-8")

    summary = {
        "events": len(events),
        "sessions_kept": len(kept),
        "prefiltered": len(filtered),
        "findings": len(findings),
        "out_dir": str(out_dir),
        "stix": stix_summary,
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
