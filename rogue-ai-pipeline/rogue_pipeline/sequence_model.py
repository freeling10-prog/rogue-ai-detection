"""Semantic action-sequence model: a first-order Markov chain over action categories, trained on BENIGN traffic.

Why it exists: Layers 1-3 lean on volume, rates and timing. An agent that throttles and jitters its requests can
slip under those, but it still has to *do* different things from benign agents - touch categories and follow
transitions that benign agents rarely do. This model scores exactly that, independent of request timing.

Model: P(next category | current category) with additive smoothing; trained with every reference agent weighted
equally (a crawler with 3 000 events counts as much as an assistant with 300). An agent's sequence surprise is
the mean surprisal in bits of a sliding window of transitions; the agent statistic is the WORST window (a short
burst of odd behaviour inside long normal traffic is what we want to see). The statistic is calibrated against
held-out reference agents (k-fold cross-fitting, so calibration is not flattered by in-sample fit):
score 0 = typical benign (median), score 1 = at or above the 99th percentile of benign agents.

Limits (also in the README): first-order only; categories are coarse; an attacker who only performs actions that
benign agents perform, in benign proportions, is invisible to it (the evaluation includes such a variant); a
benign behaviour absent from the reference set looks surprising (the evaluation includes unseen benign agents);
the longer an agent's sequence, the more windows it has to look unusual in (reference and test lengths should be
comparable). The score is a gate input to fusion, never a verdict.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np

from .config import SequenceCfg
from .schema import NormalizedEvent

UNK = "<unk>"
START = "<s>"
AGENT_WEIGHT = 200.0           # pseudo-transitions contributed by each reference agent


@dataclass
class TransitionEvidence:
    event_id: str
    from_cat: str
    to_cat: str
    bits: float
    prob: float

    def text(self) -> str:
        return f"{self.from_cat} -> {self.to_cat}: p={self.prob:.4f} ({self.bits:.1f} bits) at event {self.event_id}"


@dataclass
class SequenceResult:
    agent: str
    score: float                      # calibrated 0..1
    worst_window_bits: float
    mean_bits: float
    n_transitions: int
    top: List[TransitionEvidence] = field(default_factory=list)
    text: str = ""

    def explanation(self, ref_median: float, ref_hi: float) -> str:
        return (f"Action-sequence surprise: worst window {self.worst_window_bits:.2f} bits per transition versus a benign "
                f"median of {ref_median:.2f} and 99th percentile of {ref_hi:.2f}; unusual transitions: "
                + "; ".join(t.text() for t in self.top))


def _cats(evs: Sequence[NormalizedEvent]) -> List[Tuple[str, str]]:
    return [(e.category, e.event_id) for e in sorted(evs, key=lambda e: (e.ts, e.event_id))]


class SequenceModel:
    def __init__(self, vocab: List[str], counts: np.ndarray, cfg: SequenceCfg, lo: float = 0.0, hi: float = 1.0,
                 ref_median: float = 0.0) -> None:
        self.vocab = vocab                      # includes UNK
        self.index = {c: i for i, c in enumerate(vocab)}
        self.counts = counts                    # shape (V+1, V): row 0 = START, rows 1..V = categories
        self.cfg = cfg
        self.lo, self.hi, self.ref_median = lo, hi, ref_median

    # -- probabilities -------------------------------------------------------------------------------
    def _row(self, cat: str) -> int:
        return 1 + self.index.get(cat, self.index[UNK])

    def logprob_matrix(self) -> np.ndarray:
        a, V = self.cfg.alpha, len(self.vocab)
        c = self.counts
        return np.log2((c + a) / (c.sum(axis=1, keepdims=True) + a * V))

    def surprisals(self, cats: Sequence[str]) -> np.ndarray:
        lp = self.logprob_matrix()
        out = np.empty(max(len(cats) - 1, 0))
        for i in range(1, len(cats)):
            out[i - 1] = -lp[self._row(cats[i - 1]), self.index.get(cats[i], self.index[UNK])]
        return out

    # -- scoring -------------------------------------------------------------------------------------
    def window_stat(self, s: np.ndarray) -> Tuple[float, int]:
        """Worst sliding-window mean and the start index of that window."""
        w, st = self.cfg.window, self.cfg.step
        if len(s) <= w:
            return float(s.mean()), 0
        starts = range(0, len(s) - w + 1, st)
        means = [(float(s[i:i + w].mean()), i) for i in starts]
        return max(means)

    def score_agent(self, agent: str, evs: Sequence[NormalizedEvent]) -> Optional[SequenceResult]:
        cs = _cats(evs)
        if len(cs) - 1 < self.cfg.min_transitions:
            return None                                          # insufficient evidence: no claim
        cats = [c for c, _ in cs]
        s = self.surprisals(cats)
        worst, start = self.window_stat(s)
        score = float(np.clip((worst - self.lo) / max(self.hi - self.lo, 1e-9), 0.0, 1.0))
        w = min(self.cfg.window, len(s))
        idx = sorted(range(start, start + w), key=lambda i: -s[i])[: self.cfg.top_k]
        top = [TransitionEvidence(cs[i + 1][1], cats[i], cats[i + 1], float(s[i]), float(2.0 ** -s[i])) for i in sorted(idx)]
        res = SequenceResult(agent, score, worst, float(s.mean()), len(s), top)
        res.text = res.explanation(self.ref_median, self.hi)
        return res

    def score_all(self, by_agent: Dict[str, List[NormalizedEvent]]) -> Dict[str, SequenceResult]:
        out: Dict[str, SequenceResult] = {}
        for a, evs in by_agent.items():
            r = self.score_agent(a, evs)
            if r is not None:
                out[a] = r
        return out


def _count(by_agent: Dict[str, List[NormalizedEvent]], vocab: List[str]) -> np.ndarray:
    idx = {c: i for i, c in enumerate(vocab)}
    C = np.zeros((len(vocab) + 1, len(vocab)))
    for evs in by_agent.values():
        cats = [c for c, _ in _cats(evs)]
        if len(cats) < 2:
            continue
        A = np.zeros_like(C)
        for a, b in zip(cats[:-1], cats[1:]):
            A[1 + idx.get(a, idx[UNK]), idx.get(b, idx[UNK])] += 1
        C += A * (AGENT_WEIGHT / A.sum())
    return C


def train_sequence_model(by_agent: Dict[str, List[NormalizedEvent]], cfg: SequenceCfg, seed: int = 0) -> SequenceModel:
    """Fit on benign reference agents; calibrate lo/hi from k-fold held-out agents."""
    vocab = sorted({e.category for evs in by_agent.values() for e in evs} | {UNK})
    agents = sorted(by_agent)
    rng = np.random.default_rng(seed)
    order = rng.permutation(len(agents))
    held: List[float] = []
    for k in range(cfg.n_folds):
        test = {agents[i] for i in order[k::cfg.n_folds]}
        train = {a: by_agent[a] for a in agents if a not in test}
        m = SequenceModel(vocab, _count(train, vocab), cfg)
        for a in test:
            cs = [c for c, _ in _cats(by_agent[a])]
            if len(cs) - 1 >= cfg.min_transitions:
                held.append(m.window_stat(m.surprisals(cs))[0])
    if len(held) < 10:
        raise ValueError("not enough reference agents with long enough sequences to calibrate the sequence model")
    lo, hi = float(np.quantile(held, cfg.lo_quantile)), float(np.quantile(held, cfg.hi_quantile))
    return SequenceModel(vocab, _count(by_agent, vocab), cfg, lo, hi, float(np.median(held)))
