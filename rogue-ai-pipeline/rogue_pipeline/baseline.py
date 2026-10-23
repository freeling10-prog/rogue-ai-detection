"""Frozen baseline: train once on a benign reference set, save, load, and score single agents/sessions online.

Why: batch Isolation Forest needs a whole population in every run, so a lone visitor (say, one honeypot session)
cannot be scored. Here the forest, scaler, calibration and the Markov sequence model are fitted ONCE on historical
benign reference data and frozen. Scoring one session then needs no population.

Storage format (no pickle - loading never executes code):
  one ``.npz`` (``allow_pickle=False``) holding plain arrays (the forest's node arrays, scaler, reference
  statistics, Markov counts) plus a JSON ``manifest``: format/baseline version, creation time, library versions,
  feature + category schema, training metadata, and ``content_sha256`` - a SHA-256 over the manifest (minus that
  field) and every array. ``load_baseline`` recomputes it and refuses a mismatch. A hash stored in the same file
  detects accidental corruption and casual edits; against someone who can rewrite the whole file, pin the hash
  elsewhere and pass ``expect_sha256`` (``--baseline-sha256`` on the CLI).

The forest is evaluated by a small numpy re-implementation of Isolation Forest scoring (verified equal to
scikit-learn's ``score_samples`` in the tests), so the saved model does not depend on scikit-learn internals.
"""
from __future__ import annotations

import hashlib
import json
import platform
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import KFold
from sklearn.preprocessing import RobustScaler

from .config import Config, FrozenCfg, Layer1Cfg, SequenceCfg
from .features import FEATURE_NAMES, session_feature_vector
from .layer1_anomaly import AgentAnomaly, AnomalyResult, FeatureContribution, describe_contribution
from .schema import NormalizedEvent
from .sequence_model import SequenceModel, train_sequence_model

FORMAT_VERSION = 1
BASELINE_VERSION = "1.0"
EULER = 0.5772156649015329


class BaselineError(Exception):
    """The baseline file is unreadable, corrupt, tampered with, or incompatible with this code."""


def _c(n: np.ndarray) -> np.ndarray:
    """Average path length of an unsuccessful BST search (Liu et al. 2008); sklearn's ``_average_path_length``."""
    n = np.asarray(n, dtype=float)
    out = np.zeros_like(n)
    out[n == 2] = 1.0
    m = n > 2
    out[m] = 2.0 * (np.log(n[m] - 1.0) + EULER) - 2.0 * (n[m] - 1.0) / n[m]
    return out


@dataclass
class FrozenForest:
    """Isolation Forest as plain arrays: padded (n_trees, max_nodes) node tables."""

    left: np.ndarray        # int32
    right: np.ndarray       # int32
    feature: np.ndarray     # int16, -2 marks a leaf
    threshold: np.ndarray   # float64
    leaf_value: np.ndarray  # float64: depth + c(n_samples_in_leaf)
    c_norm: float           # c(max_samples)
    max_depth: int

    @classmethod
    def from_sklearn(cls, clf: IsolationForest) -> "FrozenForest":
        trees = [t.tree_ for t in clf.estimators_]
        width = max(t.node_count for t in trees)
        T = len(trees)
        left = np.full((T, width), -1, np.int32)
        right = np.full((T, width), -1, np.int32)
        feat = np.full((T, width), -2, np.int16)
        thr = np.zeros((T, width))
        leaf = np.zeros((T, width))
        deepest = 0
        for i, (est_feats, t) in enumerate(zip(clf.estimators_features_, trees)):
            depth = np.zeros(t.node_count, int)
            for node in range(t.node_count):                 # children always have larger ids than their parent
                for ch in (t.children_left[node], t.children_right[node]):
                    if ch != -1:
                        depth[ch] = depth[node] + 1
            n = t.node_count
            left[i, :n], right[i, :n] = t.children_left, t.children_right
            internal = t.children_left != -1
            feat[i, :n] = np.where(internal, np.asarray(est_feats)[np.where(internal, t.feature, 0)], -2)
            thr[i, :n] = t.threshold
            leaf[i, :n] = depth + _c(t.n_node_samples)
            deepest = max(deepest, int(depth.max()))
        return cls(left, right, feat, thr, leaf, float(_c(np.array([clf.max_samples_]))[0]), deepest)

    def raw_scores(self, X: np.ndarray) -> np.ndarray:
        """Anomaly score in (0,1): ~0.5 typical, towards 1 = easier to isolate (= -score_samples)."""
        X32 = np.asarray(X, dtype=np.float32)
        T, n = self.left.shape[0], X32.shape[0]
        node = np.zeros((T, n), dtype=np.int64)
        trees = np.arange(T)[:, None]
        for _ in range(self.max_depth + 1):
            f = self.feature[trees, node]
            internal = f >= 0
            if not internal.any():
                break
            val = X32[np.arange(n)[None, :], np.where(internal, f, 0)].astype(np.float64)
            go_left = val <= self.threshold[trees, node]
            nxt = np.where(go_left, self.left[trees, node], self.right[trees, node])
            node = np.where(internal, nxt, node)
        depths = self.leaf_value[trees, node].mean(axis=0)
        return 2.0 ** (-depths / self.c_norm)


@dataclass
class FrozenBaseline:
    forest: FrozenForest
    scaler_center: np.ndarray
    scaler_scale: np.ndarray
    ref_median: np.ndarray          # per-feature median over reference agents (imputation + explanation baseline)
    ref_scale: np.ndarray           # robust scale (1.4826*MAD, fallback mean abs dev) for explanation z-scores
    lo: float                       # raw score mapped to 0.0 (held-out reference quantile)
    hi: float                       # raw score mapped to 1.0
    sequence: SequenceModel
    meta: Dict[str, Any]
    content_sha256: str = ""

    # -- scoring ---------------------------------------------------------------------------------------
    def _scaled(self, X: np.ndarray) -> np.ndarray:
        return (X - self.scaler_center) / self.scaler_scale

    def raw(self, X: np.ndarray) -> np.ndarray:
        return self.forest.raw_scores(self._scaled(X))

    def calibrate(self, raw: np.ndarray) -> np.ndarray:
        return np.clip((raw - self.lo) / max(self.hi - self.lo, 1e-9), 0.0, 1.0)


# ---------------------------------------------------------------------------------------------------------
def _fit(Xs: np.ndarray, l1: Layer1Cfg) -> IsolationForest:
    return IsolationForest(n_estimators=l1.n_estimators, contamination="auto", random_state=l1.random_state).fit(Xs)


def reference_matrix(by_agent: Dict[str, List[NormalizedEvent]], fcfg: FrozenCfg) -> Tuple[List[str], np.ndarray]:
    agents = sorted(a for a, v in by_agent.items() if len(v) >= fcfg.min_session_events)
    X = np.vstack([session_feature_vector(by_agent[a], fcfg.entropy_min_span_s) for a in agents]) if agents else np.zeros((0, len(FEATURE_NAMES)))
    return agents, X


def train_baseline(by_agent: Dict[str, List[NormalizedEvent]], cfg: Config, created_at: Optional[str] = None) -> FrozenBaseline:
    """Fit the frozen baseline on benign reference data (already normalized/pseudonymized).

    Commodity-scanner clients (see ``prefilter.py``) are kept OUT of the baseline: their denied-request storms and
    sensitive-path probing would teach the model that such behaviour is normal.  The count is recorded in the metadata."""
    from .prefilter import prefilter_by_agent
    by_agent, pre = prefilter_by_agent(by_agent, cfg.web)
    f = cfg.frozen
    agents, X = reference_matrix(by_agent, f)
    if len(agents) < f.min_reference_agents:
        raise ValueError(f"need at least {f.min_reference_agents} reference agents with >= {f.min_session_events} events "
                         f"(have {len(agents)})")
    med = np.nanmedian(X, axis=0)
    Xi = np.where(np.isnan(X), med, X)
    scaler = RobustScaler().fit(Xi)
    Xs = np.nan_to_num(scaler.transform(Xi))
    clf = _fit(Xs, cfg.layer1)
    # calibrate on agents the model has NOT seen (k-fold cross-fitting)
    held = np.zeros(len(agents))
    for tr, te in KFold(f.n_folds, shuffle=True, random_state=cfg.layer1.random_state).split(Xi):
        sc = RobustScaler().fit(Xi[tr])
        m = _fit(np.nan_to_num(sc.transform(Xi[tr])), cfg.layer1)
        held[te] = -m.score_samples(np.nan_to_num(sc.transform(Xi[te])))
    lo, hi = float(np.quantile(held, f.lo_quantile)), float(np.quantile(held, f.hi_quantile))
    mad = np.median(np.abs(Xi - med), axis=0)
    mean_ad = np.mean(np.abs(Xi - med), axis=0)
    rscale = np.where(mad > 1e-9, 1.4826 * mad, np.maximum(1.2533 * mean_ad, 1e-9))
    seq = train_sequence_model({a: by_agent[a] for a in agents}, cfg.sequence)
    flag_cal = cfg.layer1.flag_threshold
    heldcal = np.clip((held - lo) / max(hi - lo, 1e-9), 0, 1)
    meta = {
        "baseline_version": BASELINE_VERSION, "format_version": FORMAT_VERSION,
        "created_at": created_at or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "libraries": {"python": platform.python_version(), "numpy": np.__version__, "scikit-learn": sklearn.__version__},
        "feature_names": list(FEATURE_NAMES), "categories": seq.vocab,
        "n_reference_agents": len(agents), "n_reference_events": int(sum(len(by_agent[a]) for a in agents)),
        "heldout_fraction_flagged": round(float((heldcal >= flag_cal).mean()), 4),
        "sequence_ref_median_bits": round(seq.ref_median, 4), "sequence_hi_bits": round(seq.hi, 4),
        "n_estimators": cfg.layer1.n_estimators, "synthetic_only": True,
        "n_prefiltered_scanner_agents": pre.agents,
    }
    return FrozenBaseline(FrozenForest.from_sklearn(clf), scaler.center_.copy(), scaler.scale_.copy(), med, rscale, lo, hi, seq, meta)


# ---- persistence ---------------------------------------------------------------------------------------
def _arrays(b: FrozenBaseline) -> Dict[str, np.ndarray]:
    return {
        "forest_left": b.forest.left, "forest_right": b.forest.right, "forest_feature": b.forest.feature,
        "forest_threshold": b.forest.threshold, "forest_leaf_value": b.forest.leaf_value,
        "forest_scalars": np.array([b.forest.c_norm, float(b.forest.max_depth), b.lo, b.hi]),
        "scaler_center": b.scaler_center, "scaler_scale": b.scaler_scale, "ref_median": b.ref_median,
        "ref_scale": b.ref_scale, "seq_counts": b.sequence.counts,
        "seq_scalars": np.array([b.sequence.lo, b.sequence.hi, b.sequence.ref_median]),
    }


def _digest(manifest: Dict[str, Any], arrays: Dict[str, np.ndarray]) -> str:
    h = hashlib.sha256()
    body = {k: v for k, v in manifest.items() if k != "content_sha256"}
    h.update(json.dumps(body, sort_keys=True, separators=(",", ":")).encode())
    for name in sorted(arrays):
        a = np.ascontiguousarray(arrays[name])
        h.update(f"|{name}|{a.dtype.str}|{a.shape}|".encode())
        h.update(a.tobytes())
    return h.hexdigest()


def save_baseline(b: FrozenBaseline, path: str | Path) -> str:
    """Write the baseline and return its content hash."""
    arrays = _arrays(b)
    manifest = dict(b.meta)
    manifest["sequence_cfg"] = b.sequence.cfg.model_dump()
    manifest["content_sha256"] = _digest(manifest, arrays)
    p = Path(path)
    with open(p, "wb") as fh:
        payload: Dict[str, Any] = {"manifest": np.frombuffer(json.dumps(manifest, sort_keys=True).encode(), dtype=np.uint8), **arrays}
        np.savez_compressed(fh, **payload)
    b.meta, b.content_sha256 = manifest, manifest["content_sha256"]
    return b.content_sha256


def load_baseline(path: str | Path, expect_sha256: Optional[str] = None) -> FrozenBaseline:
    """Load and verify. Raises ``BaselineError`` on any corruption, hash mismatch or schema/version incompatibility."""
    try:
        with np.load(path, allow_pickle=False) as z:
            files = {k: z[k] for k in z.files}
        manifest = json.loads(bytes(files.pop("manifest")).decode())
    except Exception as exc:
        raise BaselineError(f"cannot read baseline {path}: {type(exc).__name__}: {exc}") from exc
    if manifest.get("format_version") != FORMAT_VERSION:
        raise BaselineError(f"unsupported baseline format_version {manifest.get('format_version')!r} (this code reads {FORMAT_VERSION})")
    stored = manifest.get("content_sha256", "")
    actual = _digest(manifest, files)
    if actual != stored:
        raise BaselineError("baseline content hash mismatch: file is corrupt or was modified")
    if expect_sha256 is not None and expect_sha256.lower() != actual:
        raise BaselineError(f"baseline hash {actual} does not match the pinned hash {expect_sha256}")
    if manifest.get("feature_names") != list(FEATURE_NAMES):
        raise BaselineError("baseline was trained with a different feature set; retrain it")
    try:
        sc = files["forest_scalars"]
        forest = FrozenForest(files["forest_left"], files["forest_right"], files["forest_feature"], files["forest_threshold"],
                              files["forest_leaf_value"], float(sc[0]), int(sc[1]))
        ss = files["seq_scalars"]
        seq = SequenceModel(list(manifest["categories"]), files["seq_counts"], SequenceCfg(**manifest["sequence_cfg"]),
                            float(ss[0]), float(ss[1]), float(ss[2]))
        return FrozenBaseline(forest, files["scaler_center"], files["scaler_scale"], files["ref_median"], files["ref_scale"],
                              float(sc[2]), float(sc[3]), seq, manifest, actual)
    except KeyError as exc:
        raise BaselineError(f"baseline is missing array {exc}") from exc


# ---- online scoring ------------------------------------------------------------------------------------
class FrozenAnomalyScorer:
    """Score agents/sessions one at a time (or many) against the frozen baseline; no population needed."""

    def __init__(self, baseline: FrozenBaseline, cfg: Config) -> None:
        self.b, self.cfg = baseline, cfg

    def score_agent(self, agent: str, evs: List[NormalizedEvent]) -> Optional[AgentAnomaly]:
        f, l1 = self.cfg.frozen, self.cfg.layer1
        if len(evs) < f.min_session_events:
            return None                                                    # not enough evidence: no claim
        b = self.b
        x = session_feature_vector(evs, f.entropy_min_span_s)
        x = np.where(np.isnan(x), b.ref_median, x)
        raw = float(b.raw(x[None, :])[0])
        score = float(b.calibrate(np.array([raw]))[0])
        res = AgentAnomaly(agent, raw, score, score >= l1.flag_threshold)
        if res.flagged:
            variants = np.repeat(x[None, :], len(FEATURE_NAMES), axis=0)
            for j in range(len(FEATURE_NAMES)):
                variants[j, j] = b.ref_median[j]
            drop = raw - b.raw(variants)
            z = (x - b.ref_median) / b.ref_scale
            order = sorted(range(len(FEATURE_NAMES)), key=lambda j: (-drop[j], -abs(z[j])))
            for j in order[: l1.top_k_explanations]:
                if drop[j] <= 0 and abs(z[j]) < 2:
                    continue
                res.contributions.append(FeatureContribution(
                    FEATURE_NAMES[j], float(x[j]), float(b.ref_median[j]), float(z[j]), float(drop[j]),
                    describe_contribution(FEATURE_NAMES[j], float(x[j]), float(b.ref_median[j]), float(z[j]))))
        return res

    def score(self, by_agent: Dict[str, List[NormalizedEvent]]) -> AnomalyResult:
        out: Dict[str, AgentAnomaly] = {}
        short: List[str] = []
        for a, evs in sorted(by_agent.items()):
            r = self.score_agent(a, evs)
            if r is None:
                short.append(a)
            else:
                out[a] = r
        return AnomalyResult(out, short)
