"""End-to-end orchestration: normalize -> features -> Layer 1 / 2 / 3 -> fusion -> audit.

No network access, no side effects beyond the optional audit log and quarantine file.
"""
from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Union

from .audit import AuditLog
from .baseline import FrozenAnomalyScorer, FrozenBaseline
from .identity import IdentityGate, IdentityRegistry
from .sequence_model import SequenceModel, SequenceResult
from .config import Config, Policy, ResolvedPolicy
from .features import FeatureTable, build_feature_table, group_events
from .fusion import Lead, fuse
from .layer1_anomaly import AnomalyResult, AnomalyScorer
from .layer2_rules import RuleEngine, RuleFlag
from .layer3_graph import CoordinationDetector, GraphResult
from .normalize import NormalizationReport, Normalizer
from .pseudonymize import Pseudonymizer, ProductionKeyError


@dataclass
class PipelineResult:
    normalization: NormalizationReport
    table: Optional[FeatureTable]
    anomaly: Optional[AnomalyResult]
    flags: List[RuleFlag]
    graph: Optional[GraphResult]
    leads: List[Lead]
    pseudo: Pseudonymizer
    notes: List[str] = field(default_factory=list)
    sequence: Dict[str, SequenceResult] = field(default_factory=dict)       # Markov sequence scores (if a model was available)
    anomaly_batch: Optional[AnomalyResult] = None                           # batch Isolation Forest (always computed if >=10 agents and alternatives requested)
    anomaly_frozen: Optional[AnomalyResult] = None                          # frozen-baseline Isolation Forest (if a baseline was loaded)
    exempted: Dict[str, int] = field(default_factory=dict)                  # rule id -> events skipped by allowlists

    def lead_agents(self) -> set:
        return {l.agent for l in self.leads}


def resolve_policy(policy: Policy, pseudo: Pseudonymizer) -> ResolvedPolicy:
    """Translate raw-id policy into pseudonyms so the detection layers never see raw identifiers."""
    return ResolvedPolicy(
        declared_tools={pseudo.agent(a): frozenset(t) for a, t in policy.declared_tools.items()},
        groups={f"{g.kind}:{g.name}": frozenset(pseudo.agent(m) for m in g.members) for g in policy.suppression_groups},
        orchestrators=frozenset(pseudo.agent(g.orchestrator) for g in policy.suppression_groups if g.orchestrator),
    )


def config_fingerprint(cfg: Config) -> str:
    return hashlib.sha256(json.dumps(cfg.model_dump(), sort_keys=True, default=str).encode()).hexdigest()[:16]


class Pipeline:
    """Multi-layer detection pipeline. Construct once; ``run`` is pure with respect to its inputs."""

    def __init__(self, cfg: Config, policy: Policy, pseudo: Pseudonymizer, audit: Optional[AuditLog] = None,
                 run_tag: str = "run", baseline: Optional[FrozenBaseline] = None,
                 identity: Optional[IdentityRegistry] = None, sequence_model: Optional[SequenceModel] = None,
                 production: bool = False) -> None:
        """``baseline``: frozen Isolation Forest + sequence model (online scoring, no population needed).
        ``identity``: verified-identity registry (optional). ``sequence_model``: a stand-alone Markov model."""
        if production and not pseudo.production_validated:
            raise ProductionKeyError("production mode requires a Pseudonymizer built from a validated PIPELINE_HMAC_SECRET "
                                     "(see pseudonymize.resolve_key(production=True))")
        self.production = production
        self.cfg, self.pseudo, self.audit, self.run_tag = cfg, pseudo, audit, run_tag
        self.baseline = baseline
        self.sequence_model = sequence_model or (baseline.sequence if baseline else None)
        self.resolved = resolve_policy(policy, pseudo)
        self.normalizer = Normalizer(cfg.normalization, pseudo, IdentityGate(cfg.identity, identity))

    def run(self, items: Iterable[Union[Dict[str, Any], str]], quarantine_path: Optional[str | Path] = None,
            ephemeral_key: bool = False, alternatives: bool = False) -> PipelineResult:
        """``alternatives=True`` additionally computes the batch AND frozen anomaly results (used by the evaluation
        harness for ablations); the leads always use the frozen baseline when one is loaded, else the batch forest."""
        cfg = self.cfg
        rep = self.normalizer.process(items)           # 1. validate + quarantine + pseudonymize (BEFORE features)
        if quarantine_path:
            rep.write_quarantine(quarantine_path)
        if self.audit:
            self.audit.append("run_start", {
                "config_fingerprint": config_fingerprint(cfg), "run_tag": self.run_tag, "ephemeral_key": ephemeral_key, "production": self.production,
                "baseline_sha256": self.baseline.content_sha256 if self.baseline else None,
                "baseline_version": self.baseline.meta.get("baseline_version") if self.baseline else None,
                **rep.counts, **{f"identity.{k}": v for k, v in rep.identity_counts.items()}})
        notes: List[str] = []
        if not rep.events:
            notes.append("no valid events")
            return PipelineResult(rep, None, None, [], None, [], self.pseudo, notes)
        by_agent = group_events(rep.events)
        table = build_feature_table(rep.events, cfg.layer1.min_events)
        batch: Optional[AnomalyResult] = None
        frozen: Optional[AnomalyResult] = None
        if len(table.agents) >= 10 and (self.baseline is None or alternatives):
            batch = AnomalyScorer(cfg.layer1).score(table)          # 2a. Layer 1, batch mode (population = this batch)
        if self.baseline is not None:
            frozen = FrozenAnomalyScorer(self.baseline, cfg).score(by_agent)   # 2b. Layer 1, frozen baseline (online)
            if frozen.insufficient:
                notes.append(f"{len(frozen.insufficient)} agent(s)/session(s) had too few events to score against the frozen baseline")
        anomaly = frozen if self.baseline is not None else batch
        if anomaly is None:
            notes.append("Layer 1 skipped: fewer than 10 profiled agents and no frozen baseline (no population to compare with)")
        engine = RuleEngine(cfg.layer2, cfg.tools, self.resolved)
        flags = engine.evaluate(by_agent)                                              # 3. Layer 2
        graph = CoordinationDetector(cfg.layer3, self.resolved).detect(by_agent)      # 4. Layer 3
        seqs: Dict[str, SequenceResult] = {}
        if cfg.sequence.enabled and self.sequence_model is not None:
            seqs = self.sequence_model.score_all(by_agent)                              # 4b. Markov sequence model
        elif cfg.sequence.enabled:
            notes.append("sequence model not used: no benign reference model loaded (train one with train-baseline)")
        leads = fuse(cfg.fusion, anomaly.agents if anomaly else {}, flags, graph.clusters, self.run_tag,
                     seqs, cfg.sequence.gate)                                          # 5. fusion
        if self.audit:
            for l in leads:
                self.audit.append("lead", _audit_view(l.to_dict()))
            for c in graph.clusters:
                if c.suppressed:
                    self.audit.append("suppressed_cluster", {"members": c.members, "reasons": c.suppression_reasons})
            self.audit.append("run_end", {"leads": len(leads), "flags": len(flags),
                                          "clusters_active": len(graph.active),
                                          "clusters_suppressed": len(graph.clusters) - len(graph.active)})
        return PipelineResult(rep, table, anomaly, flags, graph, leads, self.pseudo, notes, seqs, batch, frozen,
                              dict(engine.exempted))


def _audit_view(lead: Dict[str, Any]) -> Dict[str, Any]:
    """Lead as written to the audit log: attacker-controlled capture text is replaced by its hash and length (the
    log stays tamper-evident for it without storing hostile text); the full sanitized text is in leads.json."""
    lead = copy.deepcopy(lead)                     # never mutate the lead itself: leads.json keeps the sanitized capture
    for f in lead.get("rule_flags", []):
        cap = f.get("extra", {}).get("capture")
        if cap:
            blob = json.dumps(cap, sort_keys=True)
            f["extra"]["capture"] = {"untrusted": True, "sha256": hashlib.sha256(blob.encode()).hexdigest(), "chars": len(blob)}
    return lead
