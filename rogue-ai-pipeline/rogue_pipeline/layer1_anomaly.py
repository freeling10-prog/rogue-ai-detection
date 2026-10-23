"""Layer 1: unsupervised anomaly scoring with Isolation Forest (Liu, Ting, Zhou, ICDM 2008) + explanations.

Scores are population-relative: the forest is fit on the agents of the analysed batch (transductive), so
"anomalous" means "unusual compared with the other agents in this batch". Hard guardrail (config-enforced):
this layer's weight in fusion is below the lead threshold, so it can NEVER raise a lead on its own.

Explanations: for each agent and feature, ``contribution`` = how much the anomaly score falls when that
feature is replaced with the population median (a simple counterfactual; positive = pushes toward
"anomalous"). The plain-language text pairs the agent's value with the population baseline.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler

from .config import Layer1Cfg
from .features import FEATURE_NAMES, FeatureTable, spec


@dataclass
class FeatureContribution:
    feature: str
    value: float
    baseline_median: float
    robust_z: float
    contribution: float
    text: str


@dataclass
class AgentAnomaly:
    agent: str
    raw_score: float            # isolation score in (0,1); ~0.5 typical, higher = more isolated
    score: float                # calibrated to [0,1] with Layer1Cfg.score_lo/score_hi
    flagged: bool
    contributions: List[FeatureContribution] = field(default_factory=list)


@dataclass
class AnomalyResult:
    agents: Dict[str, AgentAnomaly]
    insufficient: List[str] = field(default_factory=list)     # agents with too little evidence to score (frozen mode)

    @property
    def flagged(self) -> set:
        return {a for a, r in self.agents.items() if r.flagged}


def describe_contribution(feature: str, value: float, med: float, z: float) -> str:
    sp = spec(feature)
    direction = sp.higher_means if z > 0 else sp.lower_means
    if abs(med) > 1e-9 and value / med > 1.0 and z > 0:
        ratio = f" (about {value / med:.1f}x the typical value)"
    else:
        ratio = ""
    return (f"{sp.label}: {sp.fmt(value)} versus a population median of {sp.fmt(med)}{ratio} "
            f"- {direction} (robust z={z:+.1f}).")


class AnomalyScorer:
    """Fit Isolation Forest on a feature table and explain each agent's score."""

    def __init__(self, cfg: Layer1Cfg) -> None:
        self.cfg = cfg

    def score(self, table: FeatureTable) -> AnomalyResult:
        if len(table.agents) < 10:
            raise ValueError("need at least 10 profiled agents to estimate a population baseline")
        X = table.X
        scaler = RobustScaler().fit(X)
        Xs = np.nan_to_num(scaler.transform(X), nan=0.0, posinf=0.0, neginf=0.0)
        clf = IsolationForest(n_estimators=self.cfg.n_estimators, contamination="auto",
                              random_state=self.cfg.random_state).fit(Xs)
        raw = -clf.score_samples(Xs)
        cal = np.clip((raw - self.cfg.score_lo) / (self.cfg.score_hi - self.cfg.score_lo), 0.0, 1.0)
        med = np.median(X, axis=0)
        mad = np.median(np.abs(X - med), axis=0)
        # robust scale: 1.4826*MAD; where MAD is 0 (mostly-constant feature) fall back to 1.2533*mean abs deviation
        mean_ad = np.mean(np.abs(X - med), axis=0)
        scale = np.where(mad > 1e-9, 1.4826 * mad, np.maximum(1.2533 * mean_ad, 1e-9))
        zero = np.nan_to_num(scaler.transform(med.reshape(1, -1)), nan=0.0)[0]  # median in scaled space
        out: Dict[str, AgentAnomaly] = {}
        for i, agent in enumerate(table.agents):
            flagged = bool(cal[i] >= self.cfg.flag_threshold)
            res = AgentAnomaly(agent, float(raw[i]), float(cal[i]), flagged)
            if flagged:
                # counterfactual: set feature j to the population median and see how far the score drops
                variants = np.repeat(Xs[i:i + 1], len(FEATURE_NAMES), axis=0)
                for j in range(len(FEATURE_NAMES)):
                    variants[j, j] = zero[j]
                drop = raw[i] - (-clf.score_samples(variants))
                z = (X[i] - med) / scale
                order = sorted(range(len(FEATURE_NAMES)), key=lambda j: (-drop[j], -abs(z[j])))
                for j in order[: self.cfg.top_k_explanations]:
                    if drop[j] <= 0 and abs(z[j]) < 2:
                        continue
                    res.contributions.append(FeatureContribution(
                        FEATURE_NAMES[j], float(X[i, j]), float(med[j]), float(z[j]), float(drop[j]),
                        describe_contribution(FEATURE_NAMES[j], float(X[i, j]), float(med[j]), float(z[j]))))
            out[agent] = res
        return AnomalyResult(out)
