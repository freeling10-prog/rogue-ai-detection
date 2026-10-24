#!/usr/bin/env python3
"""Multi-model loopback Tier-2 runner (prep for mid-size / frontier evals).

Reuses Phase-1 harnesses (llm_agent prompts × seeds, Playwright variants, human control).
Does NOT download models. Does NOT scrape API keys.

Endpoints via env/config:
  - Ollama: OLLAMA_HOST (loopback only) + models list
  - OpenAI-compatible: AGENTWATCH_LLM_API_BASE + AGENTWATCH_LLM_API_KEY + model name
    (you must supply key/endpoint; runner never scrapes keys from disk/browser)

Safety:
  - Caps steps (hard ceiling via llm_agent.MAX_STEPS_HARD)
  - fetch_url / Playwright targets stay 127.0.0.1-only
  - Honeypot bind 127.0.0.1

Outputs:
  tests/data/real_llm_traces/multimodel/<model-id>/...
  comparison table markdown + JSON under the run root
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TRACES = ROOT / "tests" / "data" / "real_llm_traces" / "multimodel"
TIER2 = ROOT / "scripts" / "run_tier2_eval.py"
VENV_PY = Path(os.environ.get("AGENTWATCH_PYTHON", ROOT / ".venv" / "bin" / "python"))
OLLAMA = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")

PROMPTS = ("benign_summarizer", "aggressive_audit", "stealth_mimic")
PW_SCENARIOS = ("human_control",)  # cheap default; llm/stealth playwright need a model


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def slug(model_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", model_id).strip("_")[:80]


def list_ollama_models() -> list[str]:
    try:
        with urllib.request.urlopen(OLLAMA.rstrip("/") + "/api/tags", timeout=2) as r:
            data = json.loads(r.read().decode())
        return [m.get("name") for m in data.get("models") or [] if m.get("name")]
    except Exception:
        return []


def parse_models(raw: str | None) -> list[dict]:
    """Return list of {id, backend, model} from CLI/env.

    Examples:
      qwen2.5:3b
      ollama:qwen2.5:3b,openai:gpt-4o-mini
    """
    if not raw:
        raw = os.environ.get("AGENTWATCH_MULTIMODEL_LIST", "")
    out = []
    for part in [p.strip() for p in (raw or "").split(",") if p.strip()]:
        if part.startswith("openai:"):
            out.append({"id": slug(part), "backend": "openai", "model": part.split(":", 1)[1]})
        elif part.startswith("ollama:"):
            out.append({"id": slug(part.split(":", 1)[1]), "backend": "ollama", "model": part.split(":", 1)[1]})
        else:
            out.append({"id": slug(part), "backend": "ollama", "model": part})
    return out


def ensure_openai_env(backend: str) -> None:
    if backend != "openai":
        return
    if not os.environ.get("AGENTWATCH_LLM_API_BASE"):
        raise SystemExit(
            "OpenAI-compatible backend selected but AGENTWATCH_LLM_API_BASE is unset. "
            "Supply the base URL yourself; this runner never scrapes keys or endpoints."
        )
    if not os.environ.get("AGENTWATCH_LLM_API_KEY"):
        print("WARNING: AGENTWATCH_LLM_API_KEY unset — API calls will likely fail.", file=sys.stderr)


def run_tier2_for_model(model: dict, *, only: str, max_steps: int, port_base: int, dry_run: bool) -> dict:
    out_root = TRACES / model["id"]
    out_root.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["TIER2_MODEL"] = model["model"]
    env["TIER2_RUNS"] = str(out_root / "phase1-runs")
    if model["backend"] == "openai":
        ensure_openai_env("openai")
        env["TIER2_LLM_BACKEND"] = "openai"
    cmd = [
        str(VENV_PY if VENV_PY.is_file() else sys.executable),
        str(TIER2),
        "--model", model["model"],
        "--max-steps", str(max_steps),
        "--port-base", str(port_base),
        "--only", only,
    ]
    meta = {
        "model": model, "cmd": cmd, "started": utc_now(), "dry_run": dry_run,
        "traces_dir": str(out_root),
    }
    (out_root / "runner_meta.json").write_text(json.dumps(meta, indent=2) + "\n")
    if dry_run:
        return {"model": model["id"], "status": "dry_run", "cmd": cmd}
    # Prefer invoking tier2 if present; capture exit
    try:
        proc = subprocess.run(cmd, cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=3600)
        (out_root / "runner_stdout.txt").write_text(proc.stdout or "")
        (out_root / "runner_stderr.txt").write_text(proc.stderr or "")
        return {"model": model["id"], "status": "ok" if proc.returncode == 0 else "failed",
                "returncode": proc.returncode, "traces_dir": str(out_root)}
    except Exception as e:  # noqa: BLE001
        return {"model": model["id"], "status": "error", "error": str(e)}


def run_playwright_only(port: int, dry_run: bool) -> dict:
    """Cheap smoke path: scripted human_control against loopback honeypot (no LLM)."""
    script = ROOT / "redteam" / "playwright_agents" / "run_browser_agent.py"
    out = TRACES / "_smoke_playwright_human" / utc_now().replace(":", "")
    out.mkdir(parents=True, exist_ok=True)
    py = str(VENV_PY if VENV_PY.is_file() else sys.executable)
    # start honeypot
    leads = out / "leads.jsonl"
    hp_cmd = [py, "-m", "agentwatch", "honeypot", "--host", "127.0.0.1", "--port", str(port),
              "--log", str(leads), "--registry", str(out / "registry.json")]
    pw_cmd = [py, str(script), "--target", f"http://127.0.0.1:{port}/", "--scenario", "human_control",
              "--out", str(out / "pw.json")]
    meta = {"hp_cmd": hp_cmd, "pw_cmd": pw_cmd, "dry_run": dry_run}
    (out / "smoke_meta.json").write_text(json.dumps(meta, indent=2) + "\n")
    if dry_run:
        return {"status": "dry_run", "meta": meta}
    hp = subprocess.Popen(hp_cmd, cwd=str(ROOT), stdout=(out / "hp.log").open("w"), stderr=subprocess.STDOUT)
    try:
        # wait for port
        import socket
        t0 = time.time()
        while time.time() - t0 < 30:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                    break
            except OSError:
                time.sleep(0.15)
        else:
            return {"status": "error", "error": "honeypot did not start"}
        proc = subprocess.run(pw_cmd, cwd=str(ROOT), capture_output=True, text=True, timeout=180)
        (out / "pw_stdout.txt").write_text(proc.stdout or "")
        (out / "pw_stderr.txt").write_text(proc.stderr or "")
        return {"status": "ok" if proc.returncode == 0 else "failed", "returncode": proc.returncode, "out": str(out)}
    finally:
        hp.terminate()
        try:
            hp.wait(timeout=5)
        except Exception:
            hp.kill()


def write_comparison(results: list[dict], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "comparison.json").write_text(json.dumps({"generated": utc_now(), "results": results}, indent=2) + "\n")
    lines = [
        "# Multi-model Tier-2 comparison",
        "",
        f"Generated: {utc_now()} (UTC)",
        "",
        "| model | status | notes |",
        "|---|---|---|",
    ]
    for r in results:
        notes = r.get("error") or r.get("traces_dir") or r.get("cmd") or ""
        if isinstance(notes, list):
            notes = " ".join(str(x) for x in notes[:6])
        lines.append(f"| {r.get('model', r.get('status'))} | {r.get('status')} | {notes} |")
    lines.append("")
    lines.append("Caught/total per harness is filled when tier2 eval completes for each model.")
    lines.append("This prep runner records status + paths; re-run without `--dry-run` for full tables.")
    (out_dir / "comparison.md").write_text("\n".join(lines) + "\n")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Multi-model loopback Tier-2 runner (prep). Never scrapes keys; never pulls models.",
    )
    ap.add_argument("--models", default="", help="Comma list: qwen2.5:3b or ollama:...,openai:...")
    ap.add_argument("--discover-ollama", action="store_true", help="Add models from local Ollama /api/tags")
    ap.add_argument("--only", choices=["llm", "browser", "all"], default="all")
    ap.add_argument("--max-steps", type=int, default=15)
    ap.add_argument("--port-base", type=int, default=18100)
    ap.add_argument("--dry-run", action="store_true", help="Print/plan only; do not start honeypot or call models")
    ap.add_argument("--playwright-only", action="store_true",
                    help="Cheap smoke: scripted human_control on loopback (no LLM)")
    ap.add_argument("--list-local", action="store_true", help="Print local Ollama models and exit")
    args = ap.parse_args(argv)

    if args.list_local:
        models = list_ollama_models()
        print(json.dumps({"ollama_host": OLLAMA, "models": models}, indent=2))
        return 0

    if args.playwright_only:
        r = run_playwright_only(args.port_base, args.dry_run)
        write_comparison([r], TRACES / "_comparison")
        print(json.dumps(r, indent=2))
        return 0 if r.get("status") in ("ok", "dry_run") else 1

    models = parse_models(args.models)
    if args.discover_ollama:
        for name in list_ollama_models():
            if not any(m["model"] == name for m in models):
                models.append({"id": slug(name), "backend": "ollama", "model": name})
    if not models:
        print("No models specified. Use --models, --discover-ollama, or --playwright-only / --list-local.",
              file=sys.stderr)
        return 2

    results = []
    for i, m in enumerate(models):
        print(f"==> {m['backend']}:{m['model']}", flush=True)
        results.append(run_tier2_for_model(
            m, only=args.only, max_steps=min(args.max_steps, 25),
            port_base=args.port_base + i * 10, dry_run=args.dry_run,
        ))
    write_comparison(results, TRACES / "_comparison")
    print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
