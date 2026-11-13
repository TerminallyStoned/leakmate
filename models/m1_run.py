"""Train + score M1 (XGBoost) or its Random Forest baseline, write the contract
results JSON results/<model>/<experiment>[_<tag>].json, and (M1) SHAP outputs.

Examples
  # M1 on CIC (E2), per-query + per-host features, SHAP plots
  python -m models.m1_run --model m1 --exp E2 --data data/processed/cic/queries.parquet

  # Random Forest baseline, same features
  python -m models.m1_run --model rf --exp E2 --data data/processed/cic/queries.parquet

  # ablations
  python -m models.m1_run --model m1 --exp E2 --features query --tag ablation_query_only --data ...
  python -m models.m1_run --model m1 --exp E2 --keep-cic-leaky --tag ablation_cic_leaky --data ...
  python -m models.m1_run --model m1 --exp E2 --keep-cic-leaky qtype --tag ablation_cic_qtype --data ...

  # E4 cross-dataset: train on one table, test on another
  python -m models.m1_run --model m1 --exp E4 --data <train>.parquet --test-data <test>.parquet

  # S: shuffled rows instead of the time split (how much shuffling inflates scores)
  python -m models.m1_run --model m1 --exp S --split shuffled --data ...

Splits: the table's `split` column ("train"/"test") if present (parser / CIC
extractor output), otherwise a time-based 70/30 split on `ts`. Features are
computed once on the whole table before splitting; host windows look only
backwards in time, so this adds context across the cut without using the future.
"""
from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

from models import m1_features, m1_xgb, rf_baseline

MODULES = {"m1": m1_xgb, "rf": rf_baseline}
SCORE_MEANING = {"m1": "XGBoost P(tunnel)", "rf": "RandomForest P(tunnel)"}


def split(df: pd.DataFrame, how: str = "auto", test_frac: float = 0.3, seed: int = 42):
    if how == "shuffled":
        d = df.sample(frac=1.0, random_state=seed)
        cut = int(len(d) * (1 - test_frac))
        return d.iloc[:cut], d.iloc[cut:], f"shuffled_{int((1 - test_frac) * 100)}_{int(test_frac * 100)}"
    if "split" in df.columns:
        return df[df["split"] == "train"], df[df["split"] == "test"], "split_column"
    d = df.sort_values("ts", kind="stable")
    cut = int(len(d) * (1 - test_frac))
    return d.iloc[:cut], d.iloc[cut:], f"time_{int((1 - test_frac) * 100)}_{int(test_frac * 100)}"


def latency_ms(mod, model, df: pd.DataFrame, n: int = 200, seed: int = 0) -> float:
    """Mean wall time to score ONE raw query (features computed from the row, batch of 1)."""
    raw = df[[c for c in df.columns if not c.startswith(m1_features.PREFIX)]]
    s = raw.sample(min(n, len(raw)), random_state=seed)
    mod.score(model, s.iloc[:1])  # warm-up
    t = time.perf_counter()
    for i in range(len(s)):
        mod.score(model, s.iloc[i:i + 1])
    return (time.perf_counter() - t) * 1000 / len(s)


def _stratified_sample(df: pd.DataFrame, n: int, seed: int) -> pd.DataFrame:
    if len(df) <= n:
        return df
    parts = []
    for _, g in df.groupby("label"):
        k = max(1, int(round(n * len(g) / len(df))))
        parts.append(g.sample(min(k, len(g)), random_state=seed))
    return pd.concat(parts)


def write_shap(model, test_df: pd.DataFrame, out_dir: Path, name: str, n: int, seed: int) -> dict:
    """Global SHAP summary (JSON + beeswarm + bar plots) and example local explanations."""
    sample = _stratified_sample(test_df, n, seed)
    vals, base, X = m1_xgb.shap_values(model, sample)
    cols = model["cols"]
    absmean = np.abs(vals).mean(axis=0)
    order = np.argsort(-absmean)
    y = sample["label"].astype(int).to_numpy()
    summary = {
        "n_rows": int(len(sample)),
        "space": "log-odds (exact TreeSHAP via xgboost pred_contribs)",
        "base_value": float(np.mean(base)),
        "mean_abs_shap": {cols[j]: round(float(absmean[j]), 6) for j in order},
        "mean_shap_by_label": {str(lab): {c: round(float(v), 6) for c, v in zip(cols, vals[y == lab].mean(axis=0))}
                               for lab in np.unique(y)},
    }
    if "tool" in sample.columns:
        tools = sample["tool"].astype(str).to_numpy()
        summary["mean_abs_shap_by_tool"] = {
            t: {c: round(float(v), 6) for c, v in zip(cols, np.abs(vals[tools == t]).mean(axis=0))}
            for t in np.unique(tools)}

    # example alerts: strongest tunnels, and benign rows the model scores highest (FP candidates)
    probs = m1_xgb.score(model, sample)
    ex = {}
    for lab, key in [(1, "top_scored_tunnels"), (0, "top_scored_benign")]:
        idx = np.where(y == lab)[0]
        idx = idx[np.argsort(-probs[idx])][:5]
        exp = m1_xgb.explain(model, sample.iloc[idx], top_k=3)
        ex[key] = [{"qname": str(sample["qname"].iloc[i]), **e} for i, e in zip(idx, exp)]
    summary["examples"] = ex

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{name}_shap.json").write_text(json.dumps(summary, indent=1))

    try:  # plots are optional: the JSON above is the record
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import shap
        ex_obj = shap.Explanation(values=vals, base_values=base, data=X.to_numpy(), feature_names=cols)
        for kind in ["beeswarm", "bar"]:
            plt.figure()
            getattr(shap.plots, kind)(ex_obj, max_display=15, show=False)
            plt.title(f"M1 SHAP ({name}, n={len(sample)})")
            plt.tight_layout()
            plt.savefig(out_dir / f"{name}_{kind}.png", dpi=150)
            plt.close("all")
    except Exception as e:  # noqa: BLE001
        print(f"[m1] SHAP plots skipped ({e}); JSON summary written")
    return {"json": str(out_dir / f"{name}_shap.json"), "top5": [cols[j] for j in order[:5]]}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", choices=sorted(MODULES), required=True)
    ap.add_argument("--exp", required=True, help="E1..E5 or S")
    ap.add_argument("--data", required=True, help="query-table parquet (contract schema)")
    ap.add_argument("--test-data", help="separate test parquet (e.g. E4 cross-dataset)")
    ap.add_argument("--tag", default="", help="suffix for ablations, e.g. ablation_query_only")
    ap.add_argument("--out", default="results")
    ap.add_argument("--save-model", help="where to save the trained model (.joblib)")
    ap.add_argument("--split", choices=["auto", "shuffled"], default="auto")
    ap.add_argument("--features", choices=["query", "query+host"], default="query+host")
    ap.add_argument("--window", type=float, default=60.0, help="host window, seconds")
    ap.add_argument("--keep-cic-leaky", nargs="*", choices=sorted(m1_features.CIC_LEAKY_GROUPS), metavar="GROUP",
                    help="ablation only: keep CIC snaplen-artefact features. No value = keep all groups; "
                         f"or name groups from {sorted(m1_features.CIC_LEAKY_GROUPS)}")
    ap.add_argument("--n-estimators", type=int)
    ap.add_argument("--max-depth", type=int)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--no-shap", action="store_true", help="M1: skip SHAP outputs")
    ap.add_argument("--shap-n", type=int, default=5000, help="M1: rows sampled for SHAP")
    ap.add_argument("--latency-n", type=int, default=200)
    a = ap.parse_args(argv)

    mod = MODULES[a.model]
    if a.keep_cic_leaky is None:
        keep = False                      # default: drop every artefact group on CIC
    elif len(a.keep_cic_leaky) == 0:
        keep = True                       # bare flag: keep them all
    else:
        keep = sorted(set(a.keep_cic_leaky))
    cfg = {"host": a.features == "query+host", "window_s": a.window, "keep_cic_leaky": keep, "seed": a.seed}
    for k in ["n_estimators", "max_depth"]:
        if getattr(a, k) is not None:
            cfg[k] = getattr(a, k)

    df = pd.read_parquet(a.data)
    t0 = time.time()
    if a.test_data:
        train_df = m1_features.attach(df, cfg)
        test_df = m1_features.attach(pd.read_parquet(a.test_data), cfg)
        split_desc = f"train={a.data};test={a.test_data}"
    else:
        train_df, test_df, split_desc = split(m1_features.attach(df, cfg), a.split, seed=a.seed)
    feat_s = time.time() - t0

    t0 = time.time()
    model = mod.train(train_df, cfg)
    train_s = time.time() - t0
    if a.save_model:
        mod.save(model, a.save_model)

    t0 = time.time()
    scores = mod.score(model, test_df)
    score_s = time.time() - t0
    lat = latency_ms(mod, model, test_df, a.latency_n)

    name = f"{a.exp}{'_' + a.tag if a.tag else ''}"
    out_dir = Path(a.out) / a.model
    shap_info = None
    if a.model == "m1" and not a.no_shap:
        shap_info = write_shap(model, test_df, out_dir / "shap", name, a.shap_n, a.seed)

    dropped = m1_features.drop_list(train_df, cfg)
    res = {
        "model": a.model + (f"_{a.tag}" if a.tag else ""),
        "experiment": a.exp,
        "dataset": sorted(test_df["dataset"].astype(str).unique().tolist()) if "dataset" in test_df else None,
        "split": split_desc,
        "n_train": int(len(train_df)), "n_train_benign": int((train_df["label"] == 0).sum()),
        "n_test": int(len(test_df)),
        "scores": [float(x) for x in scores],
        "labels": [int(x) for x in test_df["label"]],
        "tools": test_df["tool"].astype(str).tolist() if "tool" in test_df else None,
        "src_hosts": test_df["src_host"].astype(str).tolist() if "src_host" in test_df else None,
        "feature_cols": model["cols"],
        "dropped_cols": dropped,
        "feature_importance": mod.feature_importance(model),
        "feature_time_s": round(feat_s, 3),
        "train_time_s": round(train_s, 3),
        "score_time_s": round(score_s, 3),
        "latency_ms_per_query": round(lat, 3),
        "score_meaning": SCORE_MEANING[a.model],
        "config": {k: v for k, v in model["cfg"].items()},
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    if a.model == "m1":
        res["best_iteration"] = model.get("best_iteration")
        res["n_val"] = model.get("n_val")
        res["shap"] = shap_info
    out = out_dir / f"{name}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(res))

    # quick sanity print only; real metrics come from the shared eval module
    y = np.array(res["labels"])
    if 0 < y.sum() < len(y):
        from sklearn.metrics import roc_auc_score
        print(f"[{res['model']}] sanity ROC-AUC {roc_auc_score(y, scores):.4f}")
    print(f"[{res['model']}] {len(model['cols'])} features (dropped {dropped or 'none'}), "
          f"train {train_s:.1f}s, latency {lat:.2f} ms/query -> {out}")
    if shap_info:
        print(f"[{res['model']}] SHAP top-5: {shap_info['top5']} -> {shap_info['json']}")
    return out


if __name__ == "__main__":
    main()
