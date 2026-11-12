"""Isolation Forest baseline for M2: unsupervised, trained on benign rows only.

Same contract interface as every model: train / score / save / load.
Features: cfg["feature_cols"] if those columns are already in the frame
(the parser's M1 features), otherwise models.qname_features is computed.
"""
from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from models import qname_features

DEFAULT_CFG = {"n_estimators": 300, "max_samples": 256, "contamination": "auto", "seed": 42,
               "feature_cols": None, "drop_cols": [], "n_jobs": -1}


def _features(df: pd.DataFrame, cols, drop=()) -> pd.DataFrame:
    if cols and all(c in df.columns for c in cols):
        X = df[cols].astype(float)
    else:
        X = qname_features.compute(df)
    return X.drop(columns=[c for c in drop if c in X.columns])


def train(train_df: pd.DataFrame, cfg: dict | None = None):
    cfg = {**DEFAULT_CFG, **(cfg or {})}
    benign = train_df[train_df["label"] == 0] if "label" in train_df else train_df
    X = _features(benign, cfg["feature_cols"], cfg["drop_cols"])
    pipe = make_pipeline(StandardScaler(), IsolationForest(
        n_estimators=cfg["n_estimators"], max_samples=cfg["max_samples"], contamination=cfg["contamination"],
        random_state=cfg["seed"], n_jobs=cfg["n_jobs"]))
    pipe.fit(X.values)
    return {"pipe": pipe, "cols": list(X.columns), "cfg": cfg}


def score(model, df: pd.DataFrame) -> np.ndarray:
    X = _features(df, model["cfg"]["feature_cols"], model["cfg"]["drop_cols"])[model["cols"]]
    return (-model["pipe"].score_samples(X.values)).astype(np.float32)  # higher = more anomalous


def save(model, path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, path)


def load(path):
    return joblib.load(path)
