"""Random Forest baseline for M1: supervised, same features as M1.

Contract interface: train / score / save / load. Score = P(tunnel).
Uses models/m1_features.py, so it sees exactly the columns M1 sees (including
the CIC leakage guard).

Like M1, it holds out the last `val_frac` of each capture's training rows by time and sets
its decision threshold on them (model["threshold"], eval.metrics.pick_threshold). The forest
is fitted on the remaining training rows; the test split is never seen.
"""
from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from eval.metrics import pick_threshold
from models import m1_features

DEFAULT_CFG = {**m1_features.DEFAULT_CFG,
               "n_estimators": 300, "max_depth": None, "min_samples_leaf": 2, "max_features": "sqrt",
               "class_weight": "balanced", **m1_features.VAL_CFG, "seed": 42, "n_jobs": -1}


def train(train_df: pd.DataFrame, cfg: dict | None = None):
    cfg = {**DEFAULT_CFG, **(cfg or {})}
    X = m1_features.features_for(train_df, cfg)
    X = X.drop(columns=[c for c in m1_features.drop_list(train_df, cfg) if c in X.columns])
    clf = RandomForestClassifier(
        n_estimators=cfg["n_estimators"], max_depth=cfg["max_depth"], min_samples_leaf=cfg["min_samples_leaf"],
        max_features=cfg["max_features"], class_weight=cfg["class_weight"], random_state=cfg["seed"],
        n_jobs=cfg["n_jobs"])
    y = train_df["label"].astype(int).to_numpy()
    # Same held-out rows as M1 (m1_features.val_mask): fit on the rest, set the threshold on them.
    val = m1_features.val_mask(train_df, cfg["val_frac"])
    held_out = val.any()
    fit = ~val if held_out else np.ones(len(y), dtype=bool)
    clf.fit(X.to_numpy()[fit], y[fit])
    model = {"clf": clf, "cols": list(X.columns), "cfg": cfg,
             "n_fit": int(fit.sum()), "n_val": int(val.sum()) if held_out else 0, "threshold": None}
    if held_out:
        # features as computed on the whole training table (host windows reach back past the cut), as for M1
        p_val = clf.predict_proba(X.to_numpy()[val])[:, list(clf.classes_).index(1)].astype(np.float32)
        model["threshold"] = pick_threshold(y[val], p_val, cfg["target_fpr"])
    return model


def score(model, df: pd.DataFrame) -> np.ndarray:
    X = m1_features.select(m1_features.features_for(df, model["cfg"]), model["cols"])
    clf = model["clf"]
    # Thread start-up dominates for a handful of rows (the live, one-query-at-a-time case),
    # so small batches are scored single-threaded.
    n_jobs = clf.n_jobs
    clf.n_jobs = 1 if len(X) < 1000 else n_jobs
    try:
        proba = clf.predict_proba(X.to_numpy())
    finally:
        clf.n_jobs = n_jobs
    pos = list(model["clf"].classes_).index(1) if 1 in model["clf"].classes_ else None
    return (proba[:, pos] if pos is not None else np.zeros(len(X))).astype(np.float32)


def feature_importance(model) -> dict:
    """Mean decrease in impurity per feature."""
    return {c: float(v) for c, v in zip(model["cols"], model["clf"].feature_importances_)}


def save(model, path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, path)


def load(path):
    return joblib.load(path)
