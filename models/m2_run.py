"""Train + score M2 (DNS-BERT) or its Isolation Forest baseline and write the
contract results JSON: results/<model>/<experiment>[_<tag>].json

Examples
  # main M2 run on CIC (BPE tokenizer), Tranco as extra benign
  python -m models.m2_run --model m2 --exp E2 --data data/processed/cic/queries.parquet \
      --tranco data/external/tranco.csv --ckpt-dir /content/drive/MyDrive/leakmate/m2_bpe

  # ablation 1: character tokenizer
  python -m models.m2_run --model m2 --exp E2 --tokenizer char --tag ablation1_char ...

  # Isolation Forest baseline
  python -m models.m2_run --model iforest --exp E2 --data data/processed/cic/queries.parquet

Splits: uses a `split` column ("train"/"test") if the table has one (parser
output); otherwise a time-based 70/30 split on `ts` (recorded in the JSON).
"""
from __future__ import annotations

import argparse
import json
import math
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import numpy as np
    import pandas as pd

    from models import iforest_baseline, m1_features, m2_dnsbert
except ModuleNotFoundError as e:
    raise SystemExit(f"Missing package '{e.name}'. Install the M2 packages with:\n"
                     "    pip install -r requirements-m2.txt\n"
                     "(CPU-only torch is enough off Colab: pip install torch --index-url "
                     "https://download.pytorch.org/whl/cpu)\n"
                     "Then check your setup with: python scripts/check_setup.py m2") from e

RESULT_DIR = {"m2": "m2", "iforest": "iforest"}


def load_tranco(path, n: int | None) -> list[str]:
    """Tranco CSV is `rank,domain` with no header."""
    df = pd.read_csv(path, header=None, names=["rank", "domain"], nrows=n)
    return df["domain"].astype(str).tolist()


def split(df: pd.DataFrame, test_frac: float = 0.3):
    if "split" in df.columns:
        return df[df["split"] == "train"], df[df["split"] == "test"], "split_column"
    d = df.sort_values("ts", kind="stable")
    cut = int(len(d) * (1 - test_frac))
    return d.iloc[:cut], d.iloc[cut:], f"time_{int((1 - test_frac) * 100)}_{int(test_frac * 100)}"


def hold_out_benign(train_df: pd.DataFrame, val_frac: float):
    """Latest `val_frac` of benign train rows (by ts) -> validation; never used for training.

    The threshold is set on these (alert above the 99th percentile = <=1% FPR),
    so the test set is never used to pick it.
    """
    benign = train_df[train_df["label"] == 0].sort_values("ts", kind="stable")
    n_val = int(len(benign) * val_frac)
    if n_val == 0:
        return train_df, benign.iloc[:0]
    val = benign.iloc[-n_val:]
    return train_df.drop(index=val.index), val


def latency_ms(mod, model, df: pd.DataFrame, n: int = 200, seed: int = 0) -> float:
    """Mean wall time to score ONE query (batch of 1), cold, as the live detector would."""
    s = df.sample(min(n, len(df)), random_state=seed)
    mod.score(model, s.iloc[:1])  # warm-up
    t = time.perf_counter()
    for i in range(len(s)):
        mod.score(model, s.iloc[i:i + 1])
    return (time.perf_counter() - t) * 1000 / len(s)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", choices=["m2", "iforest"], required=True)
    ap.add_argument("--exp", required=True, help="E1..E5 or S")
    ap.add_argument("--data", required=True, help="query-table parquet (contract schema)")
    ap.add_argument("--test-data", help="separate test parquet (e.g. E4 cross-dataset)")
    ap.add_argument("--tag", default="", help="suffix for ablations, e.g. ablation1_char")
    ap.add_argument("--out", default="results")
    ap.add_argument("--save-model", help="where to save the trained model")
    ap.add_argument("--tranco", help="Tranco CSV for extra benign names (M2 only)")
    ap.add_argument("--tranco-n", type=int, default=200_000)
    ap.add_argument("--tokenizer", choices=["bpe", "char"], default="bpe")
    ap.add_argument("--vocab-size", type=int)
    ap.add_argument("--epochs", type=int)
    ap.add_argument("--max-steps", type=int)
    ap.add_argument("--batch-size", type=int)
    ap.add_argument("--ckpt-dir")
    ap.add_argument("--device")
    ap.add_argument("--latency-n", type=int, default=200)
    ap.add_argument("--val-frac", type=float, default=0.1,
                    help="latest share of benign train rows held out to set the threshold")
    ap.add_argument("--fpr", type=float, default=0.01, help="target false-positive rate for the threshold")
    a = ap.parse_args(argv)
    for p in [a.data, a.test_data, a.tranco]:
        if p and not Path(p).exists():
            ap.error(f"{p} not found. Build or download it first (README > Quick start), "
                     "or see what is missing with: python scripts/check_setup.py data")

    df = pd.read_parquet(a.data)
    if a.test_data:
        test_df = pd.read_parquet(a.test_data)
        test_df.index = test_df.index + len(df)  # keep row ids unique across the two tables
        train_df, split_desc = df, f"train={a.data};test={a.test_data}"
    else:
        train_df, test_df, split_desc = split(df)

    train_df, val_df = hold_out_benign(train_df, a.val_frac)

    if a.model == "m2":
        mod = m2_dnsbert
        cfg = {"tokenizer": a.tokenizer}
        for k in ["vocab_size", "epochs", "max_steps", "batch_size", "ckpt_dir", "device"]:
            if getattr(a, k) is not None:
                cfg[k] = getattr(a, k)
        if a.tranco:
            cfg["extra_benign"] = load_tranco(a.tranco, a.tranco_n)
    else:
        mod, cfg = iforest_baseline, {}
        # M1 features computed once on the whole table, so a host's past-only window
        # can reach back across the train/test cut (same as m1_run). The CIC leakage
        # guard inside m1_features drops the snaplen artefacts.
        full = m1_features.attach(pd.concat([train_df, val_df, test_df]))
        train_df, val_df, test_df = full.loc[train_df.index], full.loc[val_df.index], full.loc[test_df.index]

    t0 = time.time()
    model = mod.train(train_df, cfg)
    train_s = time.time() - t0
    if a.save_model:
        mod.save(model, a.save_model)

    t0 = time.time()
    extra = {}
    if a.model == "m2":  # one pass gives both the PPL score and bits per query
        mean_nll, tot_nll = m2_dnsbert._score_both(model, test_df, None)
        scores = mean_nll.astype(np.float32)
        extra["info_bits"] = [round(float(x) / math.log(2), 3) for x in tot_nll]
    else:
        scores = mod.score(model, test_df)
    score_s = time.time() - t0
    lat = latency_ms(mod, model, test_df, a.latency_n)
    threshold = float(np.quantile(mod.score(model, val_df), 1 - a.fpr)) if len(val_df) else None

    used_cfg = model.cfg if hasattr(model, "cfg") else model["cfg"]
    used_cfg = {k: v for k, v in used_cfg.items() if k != "extra_benign"}
    if a.model == "m2":
        used_cfg["tranco"] = {"path": a.tranco, "n": a.tranco_n} if a.tranco else None
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
        **extra,
        "train_time_s": round(train_s, 3),
        "score_time_s": round(score_s, 3),
        "latency_ms": round(lat, 3),               # contract / eval module name
        "latency_ms_per_query": round(lat, 3),     # kept for older readers
        "threshold": threshold,
        "threshold_source": f"validation: latest {a.val_frac:.0%} of benign train, {1 - a.fpr:.0%} quantile",
        "n_val_benign": int(len(val_df)),
        "score_meaning": "pseudo-log-perplexity (mean masked-token NLL)" if a.model == "m2"
        else "negative IsolationForest score_samples",
        "config": used_cfg,
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    out = Path(a.out) / RESULT_DIR[a.model] / f"{a.exp}{'_' + a.tag if a.tag else ''}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(res))

    # quick sanity print only; real metrics come from the shared eval module
    y = np.array(res["labels"])
    if 0 < y.sum() < len(y):
        from sklearn.metrics import roc_auc_score
        print(f"[{res['model']}] sanity ROC-AUC {roc_auc_score(y, scores):.4f}")
    print(f"[{res['model']}] train {train_s:.1f}s, latency {lat:.2f} ms/query -> {out}")
    return out


if __name__ == "__main__":
    main()
