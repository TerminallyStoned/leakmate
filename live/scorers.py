"""Scorers for the live sniffer: any model that follows the contract interface (M1 by default), and a placeholder.

Both expose `name`, `threshold`, `score(df)` and `explain(df)`. `df` is a batch of query-table rows
(ts, src_host, qname, qtype, resp_size, rcode, qname_truncated, qlen_wire) plus the M1 feature set as
`f_*` columns (models.m1_features.PREFIX), so M1 scores them as they are and name-only models read qname.
"""

from __future__ import annotations

import importlib
from pathlib import Path

import numpy as np
import pandas as pd

from eval.run import ALIASES
from models.m1_features import PREFIX

DEFAULT_THRESHOLD = 0.5
# What `python -m live` runs when no --model is given: M1, the model the selection picks with the lab domain
# hidden (results_nozone/selection.csv), from the file the Experiment 1 run saves (eval/run.py).
DEFAULT_MODEL = "m1"
M1_WEIGHTS = "artifacts/m1_xgb/E1.pt"


class DummyScorer:
    """Placeholder (`--model dummy`). NOT a detector.

    Scores a query by the length of its name alone: 0 up to 40 characters, 1 from 100 characters, linear
    in between. It exists so the sniffer, the feature windows and alerts.db can be exercised without a model."""

    name = "dummy"
    FEATURES = ("q_len", "entropy", "h_qpm")

    def __init__(self, threshold: float | None = None) -> None:
        self.threshold = DEFAULT_THRESHOLD if threshold is None else threshold

    def score(self, df: pd.DataFrame) -> np.ndarray:
        return np.clip((df[PREFIX + "q_len"].to_numpy(dtype=float) - 40.0) / 60.0, 0.0, 1.0)

    def explain(self, df: pd.DataFrame, top_k: int = 3) -> list[list[dict]]:
        cols = self.FEATURES[:top_k]
        return [
            [{"feature": c, "value": float(row[PREFIX + c]), "shap": None} for c in cols] for _, row in df.iterrows()
        ]


class ModelScorer:
    """A trained model behind the contract's model interface (docs/contracts.md, section 2).

    Only `load` and `score` are required. If the module also has `explain(model, df, top_k)` (M1 does: exact
    TreeSHAP), alerts carry its top features; otherwise they carry none."""

    def __init__(self, module: str, weights: str, threshold: float | None = None) -> None:
        names = ALIASES.get(module, [module])
        if len(names) != 1:
            raise SystemExit(f"--model {module} is several models; pick one: {', '.join(names)}")
        self.name = names[0]
        self.mod = importlib.import_module(f"models.{self.name}")
        self.model = self.mod.load(weights)
        own = self.model.get("threshold") if isinstance(self.model, dict) else getattr(self.model, "threshold", None)
        if threshold is None and own is None:  # M2 and the Isolation Forest keep it in the results JSON only
            raise SystemExit(
                f"{weights} has no threshold of its own: pass --threshold, "
                "the `threshold` key of the run's results file in results/<model>/"
            )
        self.threshold = float(own) if threshold is None else threshold

    def score(self, df: pd.DataFrame) -> np.ndarray:
        return np.asarray(self.mod.score(self.model, df), dtype=float)

    def explain(self, df: pd.DataFrame, top_k: int = 3) -> list[list[dict]]:
        if not hasattr(self.mod, "explain"):
            return [[] for _ in range(len(df))]
        return [e["top"] for e in self.mod.explain(self.model, df, top_k)]


def load_scorer(model: str = DEFAULT_MODEL, weights: str | None = None, threshold: float | None = None):
    """The scorer for `--model`. M1, the default, loads M1_WEIGHTS when no file is named."""
    if model == "dummy":
        return DummyScorer(threshold)
    if not weights and ALIASES.get(model, [model]) == ["m1_xgb"]:
        weights = M1_WEIGHTS
        if not Path(weights).exists():  # never fall back to the placeholder: it is not a detector
            raise SystemExit(
                f"{weights} not found: the live detector runs M1 by default and needs its trained model.\n"
                '  - from the shared Drive: artifacts/m1_xgb/E1.pt in "leakmate captures"/m1/m1rf_valthr.zip\n'
                "  - or retrain (about 30 s, needs data/processed/testbed):\n"
                "      python -m eval.run --model m1 --exp E1 --results-dir /tmp/live\n"
                "    then pass --weights artifacts/live/m1_xgb/E1.pt\n"
                "  - or pass --model dummy for the placeholder scorer (pipeline test only, not a detector)"
            )
    if not weights:
        raise SystemExit(f"--model {model} needs --weights <file saved by that model's save()>")
    return ModelScorer(model, weights, threshold)
