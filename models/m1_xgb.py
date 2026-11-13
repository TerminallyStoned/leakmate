"""M1: XGBoost on per-query + per-host features, with SHAP explanations.

Contract interface: train(train_df, cfg) -> model, score(model, df) -> np.ndarray
(higher = more suspicious; here P(tunnel)), save, load. Plus:
  explain(model, df, top_k)  top SHAP contributions per row (for alerts / dashboard)
  shap_values(model, df)     full SHAP matrix (log-odds), one column per feature

SHAP values come from XGBoost's built-in TreeSHAP (`pred_contribs=True`), which
is exact for tree ensembles and needs no extra dependency at scoring time. The
`shap` package is only used by m1_run to draw the summary plots.

Features: models/m1_features.py (same inputs as the RF baseline). On CIC the
snaplen-leaky columns are dropped automatically (see m1_features.CIC_LEAKY).

Early stopping uses a time-based validation slice of the TRAINING data: within
each capture file (or each class, if there is no source_file column) the last
`val_frac` of rows by ts. The test split is never seen during training.
"""
from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import xgboost as xgb

from models import m1_features

DEFAULT_CFG = {**m1_features.DEFAULT_CFG,
               "n_estimators": 500, "max_depth": 6, "learning_rate": 0.1, "subsample": 0.8,
               "colsample_bytree": 0.8, "min_child_weight": 1.0, "reg_lambda": 1.0,
               "scale_pos_weight": "auto", "early_stopping_rounds": 30, "val_frac": 0.15,
               "seed": 42, "n_jobs": -1}


def _val_split(df: pd.DataFrame, frac: float):
    """Boolean mask of validation rows: last `frac` by ts within each source file (or class)."""
    if frac <= 0 or len(df) < 20:
        return np.zeros(len(df), dtype=bool)
    key = "source_file" if "source_file" in df.columns else "label"
    order = df["ts"] if "ts" in df.columns else pd.Series(np.arange(len(df)), index=df.index)
    rank = order.groupby(df[key]).rank(method="first", pct=True)
    return (rank > 1 - frac).to_numpy()


def _matrix(df: pd.DataFrame, model_or_cfg) -> pd.DataFrame:
    cfg = model_or_cfg["cfg"] if "cfg" in model_or_cfg else model_or_cfg
    X = m1_features.features_for(df, cfg)
    if "cols" in model_or_cfg:
        return m1_features.select(X, model_or_cfg["cols"])
    return X


def train(train_df: pd.DataFrame, cfg: dict | None = None):
    cfg = {**DEFAULT_CFG, **(cfg or {})}
    X = _matrix(train_df, cfg)
    X = X.drop(columns=[c for c in m1_features.drop_list(train_df, cfg) if c in X.columns])
    y = train_df["label"].astype(int).to_numpy()

    val = _val_split(train_df, cfg["val_frac"])
    use_es = bool(cfg["early_stopping_rounds"]) and val.any() \
        and len(np.unique(y[val])) == 2 and len(np.unique(y[~val])) == 2
    tr = ~val if use_es else np.ones(len(y), dtype=bool)

    spw = cfg["scale_pos_weight"]
    if spw == "auto":
        pos = max(int(y[tr].sum()), 1)
        spw = float((len(y[tr]) - pos) / pos)

    clf = xgb.XGBClassifier(
        n_estimators=cfg["n_estimators"], max_depth=cfg["max_depth"], learning_rate=cfg["learning_rate"],
        subsample=cfg["subsample"], colsample_bytree=cfg["colsample_bytree"],
        min_child_weight=cfg["min_child_weight"], reg_lambda=cfg["reg_lambda"], scale_pos_weight=spw,
        # Early stopping uses the LAST metric. AUC-PR saturates at 1.0 within a few trees on easy data
        # (CIC), which would freeze the model with uncalibrated ~0.4/0.6 scores; logloss keeps
        # improving until the probabilities are confident, so it decides when to stop.
        tree_method="hist", eval_metric=["aucpr", "logloss"], random_state=cfg["seed"], n_jobs=cfg["n_jobs"],
        early_stopping_rounds=cfg["early_stopping_rounds"] if use_es else None)
    if use_es:
        clf.fit(X[tr], y[tr], eval_set=[(X[val], y[val])], verbose=False)
    else:
        clf.fit(X, y, verbose=False)

    best = getattr(clf, "best_iteration", None) if use_es else None
    used = {**cfg, "scale_pos_weight": spw}
    return {"clf": clf, "cols": list(X.columns), "cfg": used,
            "best_iteration": None if best is None else int(best),
            "n_fit": int(tr.sum()), "n_val": int(val.sum()) if use_es else 0}


def _iter_range(model):
    b = model.get("best_iteration")
    return (0, b + 1) if b is not None else None


def score(model, df: pd.DataFrame) -> np.ndarray:
    X = _matrix(df, model)
    p = model["clf"].predict_proba(X, iteration_range=_iter_range(model))[:, 1]
    return p.astype(np.float32)  # P(tunnel); higher = more suspicious


def shap_values(model, df: pd.DataFrame):
    """(values [n, n_features], base_value [n], X) -- exact TreeSHAP in log-odds."""
    X = _matrix(df, model)
    dm = xgb.DMatrix(X, feature_names=model["cols"])
    kw = {"iteration_range": _iter_range(model)} if _iter_range(model) else {}
    contrib = model["clf"].get_booster().predict(dm, pred_contribs=True, **kw)
    return contrib[:, :-1], contrib[:, -1], X


def explain(model, df: pd.DataFrame, top_k: int = 3) -> list[dict]:
    """Per row: P(tunnel) and the top_k features pushing it towards 'tunnel'."""
    vals, _, X = shap_values(model, df)
    probs = score(model, df)
    out = []
    for i in range(len(X)):
        idx = np.argsort(-vals[i])[:top_k]
        out.append({"score": float(probs[i]),
                    "top": [{"feature": model["cols"][j], "value": float(X.iat[i, j]),
                             "shap": float(vals[i, j])} for j in idx]})
    return out


def feature_importance(model) -> dict:
    """XGBoost total gain per feature (complements mean |SHAP|)."""
    gain = model["clf"].get_booster().get_score(importance_type="total_gain")
    return {c: float(gain.get(c, 0.0)) for c in model["cols"]}


def save(model, path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, path)


def load(path):
    return joblib.load(path)
