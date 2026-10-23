#!/usr/bin/env python3
"""Command-line entry point for the rogue-AI detection pipeline (SYNTHETIC DATA ONLY, defensive use only).

Subcommands: demo | generate | detect | train-baseline | inspect-baseline | ingest-coordination | evaluate |
             verify-log | export-stix | check-atlas | selftest
No subcommand opens a network connection. Leads are for human review; nothing here blocks or punishes an agent.

Key handling: dev uses $ROGUE_PIPELINE_HMAC_KEY (or --ephemeral-key for demos). `--production` or PIPELINE_ENV=production
switches to production mode: ONLY a strong $PIPELINE_HMAC_SECRET is accepted, with no fallback (exit code 6 otherwise).
Exit codes: 0 ok, 2 tampering found, 3 STIX invalid, 4 ATLAS mismatch, 5 missing/short dev key, 6 production key refused,
7 baseline / identity registry unusable.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from rogue_pipeline import __version__
from rogue_pipeline.atlas import verify_against_yaml
from rogue_pipeline.audit import AuditLog, verify_log
from rogue_pipeline.config import load_config, load_policy, Policy
from rogue_pipeline.evaluation import format_markdown, run_evaluation
from rogue_pipeline.pipeline import Pipeline, PipelineResult
from rogue_pipeline.baseline import BaselineError, load_baseline, save_baseline, train_baseline
from rogue_pipeline.features import group_events
from rogue_pipeline.identity import IdentityRegistry, RegistryError
from rogue_pipeline.ingest import coordination_to_raw
from rogue_pipeline.normalize import Normalizer
from rogue_pipeline.pseudonymize import (KeyConfigError, MissingKeyError, ProductionKeyError, PRODUCTION_SECRET_ENV, Pseudonymizer,
                                         production_requested, resolve_key)
from rogue_pipeline.reporting import leads_to_markdown
from rogue_pipeline.simulator import SimData, build, sim_identity
from rogue_pipeline.stix_export import build_bundle, validate_bundle

ROOT = Path(__file__).resolve().parent
DEFAULT_CONFIG = ROOT / "config" / "default.toml"


def _pseudo(args: argparse.Namespace, cfg) -> tuple[Pseudonymizer, bool]:
    prod = bool(getattr(args, "production", False))
    key, eph, mode = resolve_key(cfg.pseudonymization.key_env, cfg.pseudonymization.min_key_bytes, production=prod,
                                 allow_ephemeral=bool(getattr(args, "ephemeral_key", False)))
    dev_name, both = cfg.pseudonymization.key_env, bool(os.environ.get(cfg.pseudonymization.key_env)) and bool(os.environ.get(PRODUCTION_SECRET_ENV))
    if mode == "production":
        print(f"[key] production mode: using {PRODUCTION_SECRET_ENV} ({len(key)} bytes, passed strength checks)"
              + (f"; {dev_name} is set but IGNORED in production" if os.environ.get(dev_name) else ""))
    elif both:
        print(f"[key] dev mode: using {dev_name}; {PRODUCTION_SECRET_ENV} is set but not used outside production mode")
    elif eph:
        print("[key] EPHEMERAL in-memory key (demo only): pseudonyms will not be reproducible across runs")
    return Pseudonymizer(key, cfg.pseudonymization.digest_hex_len, cfg.pseudonymization.min_key_bytes,
                         production_validated=(mode == "production")), eph


def _load_baseline(args: argparse.Namespace):
    path = getattr(args, "baseline", None)
    return load_baseline(path, getattr(args, "expect_baseline_sha256", None)) if path else None


def _load_registry(args: argparse.Namespace, cfg):
    path = getattr(args, "identity_registry", None)
    return IdentityRegistry.from_file(path, min_key_bytes=cfg.pseudonymization.min_key_bytes) if path else None


def _write_outputs(res: PipelineResult, out: Path) -> None:
    (out / "leads.json").write_text(json.dumps([l.to_dict() for l in res.leads], indent=2, sort_keys=True))
    (out / "leads.md").write_text(leads_to_markdown(res.leads, res.normalization, res.notes))


def _run(data_items: List[Any], policy: Policy, args: argparse.Namespace, out: Path, truth: Optional[SimData] = None,
         cfg=None, baseline=None, registry=None) -> int:
    cfg = cfg or load_config(args.config)
    pseudo, eph = _pseudo(args, cfg)
    baseline = baseline or _load_baseline(args)
    registry = registry or _load_registry(args, cfg)
    out.mkdir(parents=True, exist_ok=True)
    log_path = out / "audit.jsonl"
    if log_path.exists() and not args.append_log:
        log_path.unlink()
        Path(str(log_path) + ".head").unlink(missing_ok=True)
    pipe = Pipeline(cfg, policy, pseudo, AuditLog(log_path), run_tag=f"cli-{args.command}", baseline=baseline, identity=registry,
                    production=bool(getattr(args, "production", False)))
    if baseline is not None:
        print(f"[baseline] frozen baseline v{baseline.meta.get('baseline_version')} sha256={baseline.content_sha256[:16]}... "
              f"({baseline.meta.get('n_reference_agents')} reference agents, created {baseline.meta.get('created_at')})")
    res = pipe.run(data_items, quarantine_path=out / "quarantine.jsonl", ephemeral_key=eph)
    _write_outputs(res, out)
    print(f"[normalize] {res.normalization.counts}")
    for n in res.notes:
        print(f"[note] {n}")
    if res.graph:
        print(f"[layer3] state edges: {res.graph.n_state_edges}; clusters: {len(res.graph.active)} active, {len(res.graph.clusters) - len(res.graph.active)} suppressed")
        for c in res.graph.clusters:
            if c.suppressed:
                print(f"         suppressed {len(c.members)} agents: {'; '.join(r.split(':')[0] for r in c.suppression_reasons)}")
    print(f"[fusion] {len(res.leads)} lead(s) for human review (all severity=low, automatic_action=none)")
    if res.exempted:
        print(f"[identity] events exempted from rules by verified identity / allowlists: {res.exempted}; identity={res.normalization.identity_counts}")
    for l in res.leads[:15]:
        print(f"   {l.lead_id} {l.agent} score={l.score} rules={sorted({f.rule_id for f in l.rule_flags})} "
              f"cluster={'y' if l.cluster else 'n'} seq={'y' if l.sequence else 'n'}")
    if truth is not None:
        inv = {pseudo.agent(a): a for a in truth.labels}
        hit = [truth.labels[inv[l.agent]][1] for l in res.leads if inv[l.agent] in truth.labels]
        pos = sum(truth.labels[inv[l.agent]][0] == "positive" for l in res.leads)
        print(f"[truth] {pos} of {len(res.leads)} leads are injected scenarios; groups: {sorted(set(hit))}")
    print(f"[audit] {log_path} head={AuditLog(log_path).head[:16]}...  verify with: python run.py verify-log --log {log_path}")
    print(f"[out] {out}/leads.json leads.md quarantine.jsonl audit.jsonl")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    data = build(args.seed, evasive=args.evasive, n_malformed=args.malformed, extended=getattr(args, "extended", False))
    policy = load_policy(args.policy) if args.policy else data.policy
    cfg = load_config(args.config)
    baseline = registry = None
    if getattr(args, "extended", False):
        registry, idcfg = sim_identity()                        # simulated partner key + allow-listed egress range
        cfg = cfg.model_copy(update={"identity": idcfg})
    if getattr(args, "frozen", False):
        from rogue_pipeline.evaluation import _reference_by_agent
        baseline = train_baseline(_reference_by_agent(cfg, (1000, 1001, 1002), 60), cfg)
        print("[demo] trained an in-memory frozen baseline on simulated BENIGN reference data (seeds 1000-1002)")
    print(f"[demo] SYNTHETIC data: {len(data.events)} events, {len(data.labels)} agents, {len(data.malformed)} malformed records injected")
    return _run(data.all_items(), policy, args, Path(args.out), truth=data, cfg=cfg, baseline=baseline, registry=registry)


def cmd_generate(args: argparse.Namespace) -> int:
    data = build(args.seed, evasive=args.evasive, n_malformed=args.malformed, extended=getattr(args, "extended", False),
                 positives=not getattr(args, "benign_only", False))
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "events.jsonl", "w") as fh:
        for e in data.all_items():
            fh.write((e if isinstance(e, str) else json.dumps(e)) + "\n")
    (out / "policy.json").write_text(data.policy.model_dump_json(indent=2))
    (out / "labels.json").write_text(json.dumps({a: list(v) for a, v in sorted(data.labels.items())}, indent=1))
    print(f"wrote {out}/events.jsonl policy.json labels.json (synthetic ground truth: labels.json)")
    return 0


def cmd_detect(args: argparse.Namespace) -> int:
    items: List[Any] = [ln for ln in Path(args.events).read_text().splitlines() if ln.strip()]
    for f in args.coordination or []:
        recs, counts = coordination_to_raw(Path(f).read_text().splitlines(), synthetic=args.label_synthetic)
        print(f"[ingest] {f}: {counts}")
        items.extend(recs)
    return _run(items, load_policy(args.policy), args, Path(args.out))


def cmd_ingest(args: argparse.Namespace) -> int:
    """Convert agent-watch ``agentwatch.coordination-event/1`` JSONL to RawEvent JSONL."""
    recs, counts = coordination_to_raw(Path(args.input).read_text().splitlines(), synthetic=args.label_synthetic)
    Path(args.out).write_text("".join(json.dumps(r, separators=(",", ":")) + "\n" for r in recs))
    print(f"[ingest] wrote {len(recs)} RawEvent record(s) to {args.out}: {counts}")
    return 0


def cmd_train(args: argparse.Namespace) -> int:
    """Fit the frozen baseline on BENIGN reference events, save it with a version and content hash."""
    cfg = load_config(args.config)
    pseudo, _ = _pseudo(args, cfg)
    if args.simulate_reference:
        from rogue_pipeline.evaluation import _reference_by_agent
        seeds = range(args.reference_seed, args.reference_seed + args.reference_sets)
        by_agent = _reference_by_agent(cfg, seeds, 60)
        print(f"[train] SYNTHETIC benign reference from seeds {list(seeds)}")
    else:
        items = [ln for ln in Path(args.events).read_text().splitlines() if ln.strip()]
        rep = Normalizer(cfg.normalization, pseudo).process(items)
        print(f"[train] normalized reference: {rep.counts}")
        by_agent = group_events(rep.events)
    b = train_baseline(by_agent, cfg)
    digest = save_baseline(b, args.baseline_out)
    print(f"[train] reference agents={b.meta['n_reference_agents']} events={b.meta['n_reference_events']} "
          f"held-out agents flagged at the default threshold={b.meta['heldout_fraction_flagged']}")
    print(f"[train] saved {args.baseline_out}  version={b.meta['baseline_version']}  sha256={digest}")
    print("[train] REMINDER: the reference set must be benign. Anything malicious in it is learned as normal.")
    return 0


def cmd_inspect_baseline(args: argparse.Namespace) -> int:
    b = load_baseline(args.baseline, args.expect_sha256)
    print(json.dumps({**b.meta, "content_sha256": b.content_sha256}, indent=2, sort_keys=True))
    return 0


def cmd_evaluate(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    res = run_evaluation(range(args.seeds), [float(x) for x in args.levels.split(",")], cfg, extended=not args.v1)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "evaluation.json").write_text(json.dumps(res, indent=2))
    md = format_markdown(res)
    (out / "evaluation.md").write_text(md)
    print(md)
    print(f"[out] {out}/evaluation.json evaluation.md")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    r = verify_log(args.log, args.anchor)
    print(("VERIFIED " if r.ok else "TAMPERING DETECTED ") + r.message)
    if r.ok and r.head:
        print(f"head hash (store this somewhere else as an anchor): {r.head}")
    return 0 if r.ok else 2


def cmd_stix(args: argparse.Namespace) -> int:
    leads = json.loads(Path(args.leads).read_text())
    if args.confirm_all_synthetic:
        print("[stix] --confirm-all-synthetic: treating EVERY lead as human-confirmed. Demo only; never do this with real data.")
        confirmed = [l["lead_id"] for l in leads]
    else:
        confirmed = args.confirm or []
    if not confirmed:
        print("[stix] nothing confirmed: pass --confirm LEAD_ID [...] (a human decision) - nothing exported")
        return 1
    try:
        bundle = build_bundle(leads, confirmed)
    except ValueError as exc:
        print(f"[stix] error: {exc}. (Lead ids depend on the pseudonymization secret: use the same secret as the run that "
              f"produced these leads.)", file=sys.stderr)
        return 1
    text = bundle.serialize(pretty=True)
    Path(args.out).write_text(text)
    v = validate_bundle(text)
    print(f"[stix] wrote {args.out}\n[stix] {v.summary()}")
    for m in v.validator_messages[:10]:
        print("   validator error:", m)
    for m in sorted(set(w.split(": ", 1)[-1] for w in v.validator_warnings))[:5]:
        print("   validator warning (SHOULD-level):", m)
    return 0 if v.parsed_ok and (v.validator_ok in (True, None)) else 3


def cmd_atlas(args: argparse.Namespace) -> int:
    probs = verify_against_yaml(args.yaml)
    print("ATLAS ids match the local YAML" if not probs else "PROBLEMS: " + "; ".join(probs))
    return 0 if not probs else 4


def cmd_selftest(args: argparse.Namespace) -> int:
    """End-to-end smoke test in a temp dir: demo -> verify -> tamper copy -> verify must fail -> STIX."""
    os.environ.setdefault(load_config(args.config).pseudonymization.key_env, "selftest-" + "x" * 32)
    tmp = Path(tempfile.mkdtemp(prefix="rogue-selftest-"))
    try:
        a = argparse.Namespace(**{**vars(args), "command": "demo", "seed": 0, "evasive": 0.0, "malformed": 14, "policy": None,
                                  "out": str(tmp), "append_log": False})
        assert cmd_demo(a) == 0
        assert verify_log(tmp / "audit.jsonl").ok, "fresh log must verify"
        bad = tmp / "tampered.jsonl"
        lines = (tmp / "audit.jsonl").read_text().splitlines()
        lines[1] = lines[1].replace('"score"', '"score_x"', 1) if '"score"' in lines[1] else lines[1].replace("a", "b", 1)
        bad.write_text("\n".join(lines) + "\n")
        r = verify_log(bad)
        assert not r.ok, "tampered log must fail verification"
        print(f"[selftest] tamper detected as expected: {r.message}")
        s = argparse.Namespace(leads=str(tmp / "leads.json"), confirm=None, confirm_all_synthetic=True, out=str(tmp / "bundle.json"))
        assert cmd_stix(s) == 0
        try:
            resolve_key("ROGUE_PIPELINE_HMAC_KEY", production=True, env={})
            raise AssertionError("production mode must refuse a missing secret")
        except ProductionKeyError as exc:
            print(f"[selftest] production mode refuses a missing secret as expected: {str(exc)[:70]}...")
        print("[selftest] PASSED")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Rogue-AI detection pipeline (synthetic data, defensive use only).")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--config", default=str(DEFAULT_CONFIG), help="TOML thresholds (default config/default.toml)")
        sp.add_argument("--ephemeral-key", action="store_true",
                        help="use a random in-memory HMAC key (demo only) instead of $ROGUE_PIPELINE_HMAC_KEY; refused in production")
        sp.add_argument("--production", action="store_true",
                        help=f"production mode (also on if PIPELINE_ENV=production): requires a strong ${PRODUCTION_SECRET_ENV}, no fallback")
        sp.add_argument("--out", default="out")
        sp.add_argument("--append-log", action="store_true", help="continue an existing audit log instead of starting a new one")

    sp = sub.add_parser("demo", help="simulate synthetic data and run the full pipeline"); common(sp)
    sp.add_argument("--seed", type=int, default=0); sp.add_argument("--evasive", type=float, default=0.0)
    sp.add_argument("--malformed", type=int, default=14, help="number of malformed records to inject (quarantine demo)")
    sp.add_argument("--policy", default=None)
    sp.add_argument("--extended", action="store_true", help="add the v1.1 scenarios (sequence mimic, proxy rotation, partners, honeypot, ...)")
    sp.add_argument("--frozen", action="store_true", help="train an in-memory frozen baseline on simulated benign data and use it")
    sp.set_defaults(fn=cmd_demo)
    sp = sub.add_parser("generate", help="write synthetic events/policy/labels files"); common(sp)
    sp.add_argument("--seed", type=int, default=0); sp.add_argument("--evasive", type=float, default=0.0)
    sp.add_argument("--malformed", type=int, default=0); sp.add_argument("--extended", action="store_true")
    sp.add_argument("--benign-only", action="store_true", help="no injected scenarios (a benign reference set for train-baseline)")
    sp.set_defaults(fn=cmd_generate)
    sp = sub.add_parser("detect", help="run the pipeline on an events JSONL file"); common(sp)
    sp.add_argument("--events", required=True); sp.add_argument("--policy", default=None)
    sp.add_argument("--baseline", default=None, help="frozen baseline file from train-baseline (online scoring, no population needed)")
    sp.add_argument("--expect-baseline-sha256", default=None, help="refuse the baseline unless its content hash matches")
    sp.add_argument("--identity-registry", default=None, help="JSON registry of verified agent identities (keys come from env vars)")
    sp.add_argument("--coordination", nargs="*", help="agent-watch coordination-event JSONL file(s) to ingest alongside --events")
    sp.add_argument("--label-synthetic", action="store_true", help="mark ingested coordination records synthetic=true (sandbox traffic only)")
    sp.set_defaults(fn=cmd_detect)
    sp = sub.add_parser("train-baseline", help="fit + save the frozen Isolation Forest / sequence baseline on BENIGN reference data"); common(sp)
    sp.add_argument("--events", default=None, help="benign reference events JSONL"); sp.add_argument("--simulate-reference", action="store_true")
    sp.add_argument("--reference-seed", type=int, default=1000); sp.add_argument("--reference-sets", type=int, default=3)
    sp.add_argument("--baseline-out", default="baseline.npz"); sp.set_defaults(fn=cmd_train)
    sp = sub.add_parser("inspect-baseline", help="print baseline metadata and verify its content hash")
    sp.add_argument("--baseline", required=True); sp.add_argument("--expect-sha256", default=None); sp.set_defaults(fn=cmd_inspect_baseline)
    sp = sub.add_parser("ingest-coordination", help="convert agent-watch coordination-event JSONL into RawEvent JSONL")
    sp.add_argument("--in", dest="input", required=True); sp.add_argument("--out", required=True)
    sp.add_argument("--label-synthetic", action="store_true"); sp.set_defaults(fn=cmd_ingest)
    sp = sub.add_parser("evaluate", help="precision/recall/FPR on simulated scenarios"); common(sp)
    sp.add_argument("--seeds", type=int, default=5); sp.add_argument("--levels", default="0.0,0.5,1.0",
                    help="comma list of evasiveness levels (0=standard, 1=all evasive)")
    sp.add_argument("--v1", action="store_true", help="v1.0 harness (batch Isolation Forest, core scenarios only)"); sp.set_defaults(fn=cmd_evaluate)
    sp = sub.add_parser("verify-log", help="verify the hash chain of an audit log")
    sp.add_argument("--log", required=True); sp.add_argument("--anchor", default=None, help="externally stored head hash"); sp.set_defaults(fn=cmd_verify)
    sp = sub.add_parser("export-stix", help="export HUMAN-CONFIRMED leads as a STIX 2.1 bundle and validate it")
    sp.add_argument("--leads", required=True); sp.add_argument("--confirm", nargs="*", help="lead ids a human has confirmed")
    sp.add_argument("--confirm-all-synthetic", action="store_true", help="demo only: treat all leads as confirmed")
    sp.add_argument("--out", default="bundle.json"); sp.set_defaults(fn=cmd_stix)
    sp = sub.add_parser("check-atlas", help="verify ATLAS technique ids against a LOCAL ATLAS YAML file")
    sp.add_argument("--yaml", required=True); sp.set_defaults(fn=cmd_atlas)
    sp = sub.add_parser("selftest", help="end-to-end smoke test in a temp directory"); common(sp); sp.set_defaults(fn=cmd_selftest)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if hasattr(args, "production"):
        args.production = production_requested(args.production)
    try:
        if getattr(args, "production", False) and args.command in ("selftest", "evaluate"):
            raise ProductionKeyError(f"'{args.command}' uses throwaway in-process keys and is not available in production mode")
        return int(args.fn(args))
    except ProductionKeyError as exc:
        print(f"error (production mode refused to start): {exc}", file=sys.stderr)
        return 6
    except MissingKeyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 5
    except KeyConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 5
    except (BaselineError, RegistryError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 7


if __name__ == "__main__":
    sys.exit(main())
