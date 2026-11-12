"""Random Forest baseline for M1: supervised, same features as M1.

Contract interface: train / score / save / load. Score = P(tunnel).
Uses models/m1_features.py, so it sees exactly the columns M1 sees (including
the CIC leakage guard).
"""
from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from models import m1_features

DEFAULT_CFG = {**m1_features.DEFAULT_CFG,
               "n_estimators": 300, "max_depth": None, "min_samples_leaf": 2, "max_features": "sqrt",
               "class_weight": "balanced", "seed": 42, "n_jobs": -1}


def train(train_df: pd.DataFrame, cfg: dict | None = None):
    cfg = {**DEFAULT_CFG, **(cfg or {})}
    X = m1_features.features_for(train_df, cfg)
    X = X.drop(columns=[c for c in m1_features.drop_list(train_df, cfg) if c in X.columns])
    clf = RandomForestClassifier(
        n_estimators=cfg["n_estimators"], max_depth=cfg["max_depth"], min_samples_leaf=cfg["min_samples_leaf"],
        max_features=cfg["max_features"], class_weight=cfg["class_weight"], random_state=cfg["seed"],
        n_jobs=cfg["n_jobs"])
    clf.fit(X.to_numpy(), train_df["label"].astype(int).to_numpy())
    return {"clf": clf, "cols": list(X.columns), "cfg": cfg}


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
