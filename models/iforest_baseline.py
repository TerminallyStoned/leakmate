"""Isolation Forest baseline for M2: unsupervised, trained on benign rows only.

Same contract interface as every model: train / score / save / load.
Features: the M1 feature set (models/m1_features.py: per-query + per-host
window features), as the M2 card specifies, including M1's CIC leakage guard
(snaplen=96 artefacts dropped on tables from scripts/cic_to_queries.py).
Pass cfg["feature_cols"] to use the parser's feature table once it exists.
"""
from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from models import m1_features

DEFAULT_CFG = {**m1_features.DEFAULT_CFG,
               "n_estimators": 300, "max_samples": 256, "contamination": "auto", "seed": 42, "n_jobs": -1}


def train(train_df: pd.DataFrame, cfg: dict | None = None):
    cfg = {**DEFAULT_CFG, **(cfg or {})}
    benign = train_df[train_df["label"] == 0] if "label" in train_df else train_df
    X = m1_features.features_for(benign, cfg)
    X = X.drop(columns=[c for c in m1_features.drop_list(train_df, cfg) if c in X.columns])
    pipe = make_pipeline(StandardScaler(), IsolationForest(
        n_estimators=cfg["n_estimators"], max_samples=cfg["max_samples"], contamination=cfg["contamination"],
        random_state=cfg["seed"], n_jobs=cfg["n_jobs"]))
    pipe.fit(X.values)
    return {"pipe": pipe, "cols": list(X.columns), "cfg": cfg}


def score(model, df: pd.DataFrame) -> np.ndarray:
    X = m1_features.select(m1_features.features_for(df, model["cfg"]), model["cols"])
    return (-model["pipe"].score_samples(X.values)).astype(np.float32)  # higher = more anomalous


def save(model, path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, path)


def load(path):
    return joblib.load(path)
