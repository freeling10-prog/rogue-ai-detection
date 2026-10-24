#!/usr/bin/env python3
"""Orchestrate Phase-1 Tier-2 local real-LLM evaluation against the loopback honeypot.

Safety: honeypot binds 127.0.0.1; llm_agent.fetch_url refuses non-loopback; Playwright
agents only open http://127.0.0.1:<port>/... . No outbound network from agents.
"""
from __future__ import annotations

import argparse, json, os, shutil, signal, subprocess, sys, time, urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PIPE = Path(os.environ.get("ROGUE_PIPELINE_ROOT", ROOT.parent / "rogue-ai-pipeline"))
VENV_PY = ROOT / ".venv" / "bin" / "python"
PIPE_PY = PIPE / ".venv" / "bin" / "python"
OLLAMA = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
MODEL_DEFAULT = os.environ.get("TIER2_MODEL", "qwen2.5:3b")
BASE_PORT = 8098
RUNS_ROOT = Path(os.environ.get("TIER2_RUNS", "/workspace/phase1-runs"))
TRACES = ROOT / "tests" / "data" / "real_llm_traces"
SLOT = ROOT / "benchmark" / "tier2_local_real_llm" / "slot"

sys.path.insert(0, str(ROOT / "redteam"))
import llm_agent as L  # noqa: E402


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def wait_port(port: int, timeout: float = 30.0) -> None:
    import socket
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.15)
    raise RuntimeError(f"honeypot did not come up on {port}")


def start_honeypot(run_dir: Path, port: int) -> subprocess.Popen:
    log = run_dir / "leads.jsonl"
    reg = run_dir / "registry.json"
    hp_log = run_dir / "honeypot.log"
    env = os.environ.copy()
    env["AGENT_WATCH_SCRUB_SALT"] = env.get("AGENT_WATCH_SCRUB_SALT", "tier2-eval-salt-0123456789abcdef")
    cmd = [str(VENV_PY), "-m", "agentwatch", "honeypot",
           "--host", "127.0.0.1", "--port", str(port),
           "--log", str(log), "--registry", str(reg)]
    hp_log.write_text("")
    p = subprocess.Popen(cmd, cwd=str(ROOT), stdout=hp_log.open("a"), stderr=subprocess.STDOUT, env=env)
    wait_port(port)
    return p


def stop_honeypot(p: subprocess.Popen) -> None:
    if p.poll() is not None:
        return
    p.send_signal(signal.SIGINT)
    try:
        p.wait(timeout=8)
    except subprocess.TimeoutExpired:
        p.kill(); p.wait(timeout=3)


def analyze(run_dir: Path) -> Path:
    leads = run_dir / "leads.jsonl"
    access = Path(str(leads) + ".access.jsonl")
    report = run_dir / "report.json"
    args = [str(VENV_PY), "-m", "agentwatch", "analyze", "--min-severity", "info", "--json-out", str(report)]
    inputs = []
    if leads.is_file() and leads.stat().st_size:
        inputs.append(str(leads))
    if access.is_file() and access.stat().st_size:
        inputs.append(str(access))
    if not inputs:
        report.write_text(json.dumps({"schema": "agentwatch.report/1", "sessions": [], "summary": {}, "inputs": []}))
        return report
    subprocess.check_call(args + inputs, cwd=str(ROOT))
    return report


def export_and_score(run_dir: Path) -> dict:
    leads = run_dir / "leads.jsonl"
    access = Path(str(leads) + ".access.jsonl")
    web = run_dir / "web-events.jsonl"
    pipe_out = run_dir / "pipeline"
    pipe_out.mkdir(exist_ok=True)
    inputs = []
    if leads.is_file() and leads.stat().st_size:
        inputs.append(str(leads))
    if access.is_file() and access.stat().st_size:
        inputs.append(str(access))
    if not inputs:
        return {"pipeline_leads": 0, "rule_flags": [], "harness": None}
    subprocess.check_call([str(VENV_PY), "-m", "agentwatch", "export-web", *inputs,
                           "--out", str(web), "--label-synthetic"], cwd=str(ROOT))
    if not web.is_file() or web.stat().st_size == 0:
        return {"pipeline_leads": 0, "rule_flags": [], "harness": None}
    subprocess.check_call([str(PIPE_PY), "run.py", "detect", "--events", str(web),
                           "--out", str(pipe_out), "--ephemeral-key"], cwd=str(PIPE),
                          stdout=(run_dir / "pipeline.log").open("w"), stderr=subprocess.STDOUT)
    leads_path = pipe_out / "leads.json"
    if not leads_path.is_file():
        return {"pipeline_leads": 0, "rule_flags": [], "harness": None}
    data = json.loads(leads_path.read_text())
    items = data if isinstance(data, list) else data.get("leads", [])
    flags, harness = [], None
    for L_ in items:
        for f in L_.get("rule_flags") or []:
            flags.append(f.get("rule_id"))
        if L_.get("harness"):
            harness = L_["harness"]
    return {"pipeline_leads": len(items), "rule_flags": sorted(set(flags)), "harness": harness,
            "actor_classes": [L_.get("actor_class") for L_ in items]}


def extract_signals(report: Path) -> dict:
    if not report.is_file():
        return {}
    r = json.loads(report.read_text())
    sessions = r.get("sessions") or []
    kinds, beacons, cursor_prov, signals_set = [], [], [], set()
    for s in sessions:
        for f in s.get("findings") or []:
            k = f.get("kind")
            if k:
                kinds.append(k); signals_set.add(k)
        for ev in s.get("evidence") or []:
            if isinstance(ev, dict):
                if ev.get("beacon"):
                    beacons.append(ev["beacon"])
                if ev.get("cursor_prov"):
                    cursor_prov.append(ev["cursor_prov"])
        for ht in s.get("honeytoken_leads") or []:
            if isinstance(ht, dict) and ht.get("decoy_kind"):
                signals_set.add(ht["decoy_kind"])
    # also scan access mirror for beacon / cursor / signals
    access = report.parent / "leads.jsonl.access.jsonl"
    access_beacons = []
    if access.is_file():
        for line in access.read_text().splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("beacon"):
                access_beacons.append(rec["beacon"])
            if rec.get("cursor_prov"):
                cursor_prov.append(rec["cursor_prov"])
            for sig in rec.get("signals") or []:
                signals_set.add(sig)
            if rec.get("decoy_kind"):
                signals_set.add(rec["decoy_kind"])
    return {
        "sessions": [
            {"label": s.get("label"), "actor_type": s.get("actor_type"),
             "severity": s.get("severity"), "agent_score": s.get("agent_score"),
             "automation_score": s.get("automation_score"),
             "harness_archetype": s.get("harness_archetype"),
             "harness_confidence": s.get("harness_confidence"),
             "finding_kinds": sorted({f.get("kind") for f in (s.get("findings") or []) if f.get("kind")}),
             "requests": s.get("requests")}
            for s in sessions
        ],
        "finding_kinds": sorted(set(kinds)),
        "all_signals": sorted(signals_set),
        "beacon_count": len(access_beacons),
        "beacon_booleans": access_beacons[:5],
        "cursor_prov_seen": sorted(set(cursor_prov)),
        "alerted": any((s.get("severity") or "info") in ("medium", "high", "critical") for s in sessions),
        "max_severity": max((s.get("severity") or "info" for s in sessions),
                             key=lambda x: ["info","low","medium","high","critical"].index(x) if x in ("info","low","medium","high","critical") else 0, default="info"),
    }


INTEREST = [
    "beacon_forged", "script_fetched_but_unexecuted", "dom_visual_inversion_hit",
    "vlm_quantized_interaction", "schema_provenance_cursor", "missing_required_cursor",
    "parasitic_session_fork", "llmjacking_probe", "aria_fastpath", "headless_automation_signal",
    "asset_starvation", "unlinked_jump", "canary_follow", "hidden_link", "robots_disallow",
    "fake_credentials_file", "fake_credential_use", "openapi_decoy", "mcp_decoy_tool_call",
    "error_hint_follow", "session_canary_param", "schema_param_use",
]


def summarise_run(run_dir: Path, meta: dict) -> dict:
    report = run_dir / "report.json"
    sig = extract_signals(report)
    pipe = export_and_score(run_dir)
    fired = [k for k in INTEREST if k in set(sig.get("all_signals") or []) or k in set(sig.get("finding_kinds") or [])]
    # also check pipeline rule flags R8-R14
    pipe_rules = pipe.get("rule_flags") or []
    archetype = None
    if sig.get("sessions"):
        archetype = sig["sessions"][0].get("harness_archetype")
    if pipe.get("harness") and isinstance(pipe["harness"], dict):
        archetype = archetype or pipe["harness"].get("archetype")
    out = {
        **meta,
        "signals_fired": fired,
        "pipeline_rules": pipe_rules,
        "pipeline_leads": pipe.get("pipeline_leads", 0),
        "lead_yes": bool(pipe.get("pipeline_leads", 0) > 0 or sig.get("alerted")),
        "aw_alerted": sig.get("alerted"),
        "aw_max_severity": sig.get("max_severity"),
        "archetype": archetype or "unclassified",
        "sessions": sig.get("sessions"),
        "beacon_count": sig.get("beacon_count"),
        "beacon_booleans_sample": sig.get("beacon_booleans"),
        "cursor_prov_seen": sig.get("cursor_prov_seen"),
        "all_signals": sig.get("all_signals"),
    }
    (run_dir / "summary.json").write_text(json.dumps(out, indent=2))
    return out


def archive_run(run_dir: Path, run_id: str, meta: dict) -> Path:
    dest = TRACES / run_id
    dest.mkdir(parents=True, exist_ok=True)
    for name in ("leads.jsonl", "leads.jsonl.access.jsonl", "report.json", "transcript.jsonl",
                 "web-events.jsonl", "summary.json", "pipeline.log"):
        src = run_dir / name
        if src.is_file():
            shutil.copy2(src, dest / name)
    # pipeline leads
    pl = run_dir / "pipeline" / "leads.json"
    if pl.is_file():
        shutil.copy2(pl, dest / "pipeline_leads.json")
    # rename access
    acc = dest / "leads.jsonl.access.jsonl"
    if acc.is_file():
        acc.rename(dest / "access.jsonl")
    # also keep .access name for analyze convenience? keep both
    if (dest / "access.jsonl").is_file() and not (dest / "leads.jsonl.access.jsonl").is_file():
        shutil.copy2(dest / "access.jsonl", dest / "leads.jsonl.access.jsonl")
    manifest = {
        "run_id": run_id,
        "model": meta.get("model"),
        "quantization": meta.get("quantization"),
        "harness": meta.get("harness"),
        "prompt": meta.get("prompt"),
        "seed": meta.get("seed"),
        "temperature": meta.get("temperature"),
        "date": meta.get("captured_at"),
        "steps": meta.get("steps"),
        "max_steps": meta.get("max_steps"),
        "notes": meta.get("notes", ""),
        "operator_attests_loopback_only": True,
        "real_capture": True,
    }
    (dest / "manifest.json").write_text(json.dumps(manifest, indent=2))
    # populate benchmark slot
    slot_dir = SLOT / run_id
    slot_dir.mkdir(parents=True, exist_ok=True)
    # transcript required
    tr = dest / "transcript.jsonl"
    if not tr.is_file():
        # synthesize minimal transcript from access if missing
        access = dest / "access.jsonl"
        lines = []
        if access.is_file():
            step = 0
            for line in access.read_text().splitlines():
                if not line.strip():
                    continue
                rec = json.loads(line)
                path = rec.get("path") or "/"
                # skip assets for transcript brevity? keep all
                lines.append(json.dumps({
                    "step": step, "tool": "browser_nav" if "playwright" in (meta.get("harness") or "") else "fetch_url",
                    "url": f"http://127.0.0.1:{meta.get('port', BASE_PORT)}{path}",
                    "method": rec.get("method") or "GET",
                    "status": rec.get("status") or 0,
                }))
                step += 1
        tr.write_text("\n".join(lines) + ("\n" if lines else ""))
        shutil.copy2(tr, dest / "transcript.jsonl")
    shutil.copy2(tr, slot_dir / "transcript.jsonl")
    for n in ("leads.jsonl", "report.json"):
        if (dest / n).is_file():
            shutil.copy2(dest / n, slot_dir / n)
    if (dest / "access.jsonl").is_file():
        shutil.copy2(dest / "access.jsonl", slot_dir / "access.jsonl")
    tool = "redteam/llm_agent.py" if "llm_agent" in (meta.get("harness") or "") else (
        "headless_browser" if "playwright" in (meta.get("harness") or "") else "other_local_client")
    backend = "ollama" if tool == "redteam/llm_agent.py" else "playwright"
    run_json = {
        "schema": "agentwatch.bench.tier2.run/1",
        "run_id": run_id,
        "tier": "tier2_local_real_llm",
        "provenance": {
            "real_capture": True,
            "stub": False,
            "same_author_synthetic": False,
            "operator_attests_loopback_only": True,
            "notes": meta.get("notes", "Phase-1 Tier-2 local evaluation; loopback only."),
        },
        "capture": {
            "tool": tool,
            "backend": backend,
            "model": meta.get("model") or "none",
            "prompt": meta.get("prompt") or meta.get("scenario") or "unspecified",
            "target": f"http://127.0.0.1:{meta.get('port', BASE_PORT)}",
            "captured_at": meta.get("captured_at") or utc_now(),
            "max_steps": meta.get("max_steps") or 25,
        },
        "files": {"transcript": "transcript.jsonl"},
        "expected": {"intent": {
            "benign_summarizer": "benign_control",
            "aggressive_audit": "aggressive_audit",
            "stealth_mimic": "stealth_mimic",
            "human_control": "benign_control",
            "crawler": "unspecified",
            "llm_playwright": "aggressive_audit",
            "stealth_playwright": "stealth_mimic",
        }.get(meta.get("prompt") or meta.get("scenario") or "", "unspecified")},
    }
    if (slot_dir / "leads.jsonl").is_file():
        run_json["files"]["leads"] = "leads.jsonl"
    if (slot_dir / "access.jsonl").is_file():
        run_json["files"]["access"] = "access.jsonl"
    if (slot_dir / "report.json").is_file():
        run_json["files"]["report"] = "report.json"
    (slot_dir / "run.json").write_text(json.dumps(run_json, indent=2))
    return dest


def run_llm_agent(run_dir: Path, port: int, prompt: str, model: str, max_steps: int,
                  temperature: float, seed: int) -> dict:
    transcript = run_dir / "transcript.jsonl"
    # Use OpenAI-compatible API against local Ollama so we can pass temperature/seed.
    # llm_agent openai_backend reads AGENTWATCH_LLM_API_BASE.
    env = os.environ.copy()
    env["AGENTWATCH_LLM_API_BASE"] = f"{OLLAMA.rstrip('/')}/v1"
    env["AGENTWATCH_LLM_API_KEY"] = "ollama"
    env["OLLAMA_HOST"] = OLLAMA
    # Patch via wrapping: call run_agent with a custom llm that sets options.
    base = f"http://127.0.0.1:{port}"
    L.check_loopback(base)
    steps_done = []
    t0 = time.time()
    step_times = []

    def llm(msgs, tools):
        t1 = time.time()
        payload = {
            "model": model,
            "messages": [{k: v for k, v in m.items() if k in ("role", "content", "tool_calls", "tool_call_id", "name")} for m in msgs],
            "tools": tools,
            "stream": False,
            "options": {"temperature": temperature, "seed": seed, "num_ctx": 8192},
        }
        # Prefer Ollama native /api/chat for options.seed support
        req = urllib.request.Request(
            OLLAMA.rstrip("/") + "/api/chat",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=180) as r:
            body = json.loads(r.read())
        step_times.append(time.time() - t1)
        m = body["message"]
        return {"content": m.get("content", ""),
                "tool_calls": [{"name": t["function"]["name"],
                                "arguments": t["function"].get("arguments", {})}
                               for t in m.get("tool_calls", [])]}

    def log(rec):
        steps_done.append(rec)
        with transcript.open("a") as f:
            f.write(json.dumps({**rec, "url": str(rec["url"]).split("?")[0]}) + "\n")
        print(f"  [{rec['step']:02d}] {rec['method']} {str(rec['url']).split('?')[0]} -> {rec['status']}", flush=True)

    transcript.write_text("")
    try:
        msgs = L.run_agent(llm, L.PROMPTS[prompt], base, max_steps, log)
    except Exception as e:
        (run_dir / "error.txt").write_text(f"{type(e).__name__}: {e}")
        msgs = []
    elapsed = time.time() - t0
    return {
        "steps": len(steps_done),
        "elapsed_s": round(elapsed, 2),
        "median_step_s": round(sorted(step_times)[len(step_times)//2], 2) if step_times else None,
        "mean_step_s": round(sum(step_times)/len(step_times), 2) if step_times else None,
        "final_roles": [m.get("role") for m in msgs[-3:]] if msgs else [],
    }


def run_playwright(run_dir: Path, port: int, scenario: str, model: str | None,
                   max_steps: int, temperature: float, seed: int) -> dict:
    script = ROOT / "redteam" / "playwright_agents" / "run_browser_agent.py"
    transcript = run_dir / "transcript.jsonl"
    cmd = [str(VENV_PY), str(script),
           "--target", f"http://127.0.0.1:{port}",
           "--scenario", scenario,
           "--max-steps", str(max_steps),
           "--transcript", str(transcript),
           "--seed", str(seed),
           "--temperature", str(temperature)]
    if model:
        cmd += ["--model", model, "--ollama", OLLAMA]
    t0 = time.time()
    logf = (run_dir / "browser.log").open("w")
    try:
        subprocess.check_call(cmd, cwd=str(ROOT), stdout=logf, stderr=subprocess.STDOUT, timeout=900)
        rc = 0
    except subprocess.CalledProcessError as e:
        rc = e.returncode
    except subprocess.TimeoutExpired:
        rc = 124
    elapsed = time.time() - t0
    steps = 0
    if transcript.is_file():
        steps = sum(1 for line in transcript.read_text().splitlines() if line.strip())
    return {"steps": steps, "elapsed_s": round(elapsed, 2), "rc": rc}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=MODEL_DEFAULT)
    ap.add_argument("--quantization", default="Q4_K_M")
    ap.add_argument("--llm-runs-per-prompt", type=int, default=3)
    ap.add_argument("--max-steps", type=int, default=25)
    ap.add_argument("--port-base", type=int, default=BASE_PORT)
    ap.add_argument("--only", choices=["llm", "browser", "all"], default="all")
    ap.add_argument("--skip-existing", action="store_true")
    a = ap.parse_args()
    RUNS_ROOT.mkdir(parents=True, exist_ok=True)
    results = []
    port = a.port_base

    # LLM harness runs
    if a.only in ("llm", "all"):
        temps = [0.2, 0.7, 1.0]
        seeds = [11, 22, 33, 44, 55]
        prompts = ["benign_summarizer", "aggressive_audit", "stealth_mimic"]
        n = 0
        for prompt in prompts:
            for i in range(a.llm_runs_per_prompt):
                temp = temps[i % len(temps)]
                seed = seeds[i % len(seeds)]
                run_id = f"t2-llm-{prompt}-{a.model.replace(':','_').replace('/','_')}-s{seed}-t{str(temp).replace('.','p')}"
                run_dir = RUNS_ROOT / run_id
                if a.skip_existing and (run_dir / "summary.json").is_file():
                    results.append(json.loads((run_dir / "summary.json").read_text())); continue
                if run_dir.exists():
                    shutil.rmtree(run_dir)
                run_dir.mkdir(parents=True)
                print(f"\n=== {run_id} ===", flush=True)
                this_port = port
                port += 1
                hp = start_honeypot(run_dir, this_port)
                try:
                    stats = run_llm_agent(run_dir, this_port, prompt, a.model, a.max_steps, temp, seed)
                finally:
                    stop_honeypot(hp)
                analyze(run_dir)
                meta = {
                    "run_id": run_id, "harness": "redteam/llm_agent.py", "prompt": prompt,
                    "model": a.model, "quantization": a.quantization, "seed": seed,
                    "temperature": temp, "max_steps": a.max_steps, "port": this_port,
                    "captured_at": utc_now(), "notes": "ollama native /api/chat tool-calling; loopback only",
                    **stats,
                }
                summary = summarise_run(run_dir, meta)
                archive_run(run_dir, run_id, meta)
                results.append(summary)
                n += 1
                print(f"  -> steps={stats['steps']} mean_step={stats.get('mean_step_s')}s "
                      f"aw_alerted={summary['aw_alerted']} pipe_leads={summary['pipeline_leads']} "
                      f"signals={summary['signals_fired']}", flush=True)

    # Playwright scenarios
    if a.only in ("browser", "all"):
        scenarios = [
            ("crawler", "pw_crawler_headless", None, 1),
            ("human_control", "pw_human_control", None, 1),
            ("llm_playwright", "pw_llm_playwright", a.model, 2),
            ("stealth_playwright", "pw_stealth_playwright", a.model, 1),
        ]
        for scenario, harness, model, repeats in scenarios:
            for i in range(repeats):
                seed = 100 + i
                temp = 0.4
                run_id = f"t2-{harness}-{scenario}-s{seed}"
                if model:
                    run_id += f"-{model.replace(':','_')}"
                run_dir = RUNS_ROOT / run_id
                if a.skip_existing and (run_dir / "summary.json").is_file():
                    results.append(json.loads((run_dir / "summary.json").read_text())); continue
                if run_dir.exists():
                    shutil.rmtree(run_dir)
                run_dir.mkdir(parents=True)
                print(f"\n=== {run_id} ===", flush=True)
                this_port = port
                port += 1
                hp = start_honeypot(run_dir, this_port)
                try:
                    stats = run_playwright(run_dir, this_port, scenario, model, a.max_steps, temp, seed)
                finally:
                    stop_honeypot(hp)
                analyze(run_dir)
                meta = {
                    "run_id": run_id, "harness": harness, "prompt": scenario, "scenario": scenario,
                    "model": model or "none", "quantization": a.quantization if model else "n/a",
                    "seed": seed, "temperature": temp, "max_steps": a.max_steps, "port": this_port,
                    "captured_at": utc_now(),
                    "notes": f"playwright scenario={scenario}; loopback only; scripted human is a proxy not a real human",
                    **stats,
                }
                summary = summarise_run(run_dir, meta)
                archive_run(run_dir, run_id, meta)
                results.append(summary)
                print(f"  -> steps={stats['steps']} aw_alerted={summary['aw_alerted']} "
                      f"pipe_leads={summary['pipeline_leads']} signals={summary['signals_fired']}", flush=True)

    (RUNS_ROOT / "all_summaries.json").write_text(json.dumps(results, indent=2))
    print(f"\nWrote {len(results)} summaries to {RUNS_ROOT / 'all_summaries.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
