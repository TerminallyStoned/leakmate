"""Train + score M2 (DNS-BERT) or its Isolation Forest baseline and write the
contract results JSON: results/<model>/<run name>[_<tag>].json

Splits come from the shared eval/experiments.py (the same splits every model uses):
  E1  within-testbed                      E2  CIC benchmark
  E3  leave-one-tool-out (--holdout TOOL)  E4_cic2testbed / E4_testbed2cic
Or pass --data (and --test-data) to use a table directly.

Examples
  # Experiment 2 (CIC), Tranco as extra benign
  python -m models.m2_run --model m2 --exp E2 --tranco data/external/tranco.csv --ckpt-dir <dir>

  # Experiment 1 (testbed): continue pre-training the Phase 1 model on testbed benign
  python -m models.m2_run --model m2 --exp E1 --init-from <ckpt_bpe_v2>/last --lr 1e-4 \
      --save-model models/weights/m2_bpe_testbed

  # Experiment 3: M2 trains on benign only, so reuse the Experiment 1 model and just score
  python -m models.m2_run --model m2 --exp E3 --holdout iodine --load-model models/weights/m2_bpe_testbed

Per-host averaging (--host-window, seconds; 0 = off): each run also writes
<run>_hostavg.json whose score is the mean score of the same host's queries in the
past window, which catches slow tunnels that look harmless one query at a time.

Threshold: the latest --val-frac of each capture's benign training rows is held out
(never trained on); the threshold is their 1-fpr quantile.
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

    from eval.experiments import EXP_HELP, get_split
    from eval.metrics import threshold_at_fpr
    from eval.results_io import environment
    from models import iforest_baseline, m1_features, m2_dnsbert, m2_supervised
except ModuleNotFoundError as e:
    raise SystemExit(
        f"Missing package '{e.name}'. Install the M2 packages with:\n"
        "    pip install -r requirements-m2.txt\n"
        "(CPU-only torch is enough off Colab: pip install torch --index-url "
        "https://download.pytorch.org/whl/cpu)\n"
        "Then check your setup with: python scripts/check_setup.py m2"
    ) from e


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
    """Latest `val_frac` of each capture's benign train rows (by ts) -> validation; never trained on.

    Taken per capture (`source_file`) so the threshold sees every benign capture,
    not just whichever was recorded last. The threshold is set on these rows.
    """
    benign = train_df[train_df["label"] == 0]
    key = benign["source_file"] if "source_file" in benign else pd.Series("all", index=benign.index)
    val_idx = []
    for _, g in benign.groupby(key, sort=False):
        g = g.sort_values("ts", kind="stable")
        n_val = int(len(g) * val_frac)
        if n_val:
            val_idx.extend(g.index[-n_val:])
    val = benign.loc[val_idx]
    return train_df.drop(index=val.index), val


def val_threshold(val_scores, fpr: float) -> float:
    """Lowest threshold that flags at most `fpr` of the held-out benign rows, counting score >= threshold
    as an alert (eval.metrics.threshold_at_fpr, the eval module's own rule). Tie-aware: benign names that
    repeat share one score, and a plain quantile can land on such a tie and flag all of them."""
    v = np.asarray(val_scores, dtype=float)
    return threshold_at_fpr(np.zeros(len(v)), v, fpr)


def host_average(df: pd.DataFrame, scores, window_s: float) -> np.ndarray:
    """Mean score of the same host's queries in the past `window_s` seconds (inclusive).

    Host key is <source_file>|<src_host> when the table has source_file, so two
    captures that reuse an address never share a window. Past-only: no future rows.
    """
    host = df["src_host"].astype(str)
    if "source_file" in df.columns:
        host = df["source_file"].astype(str) + "|" + host
    tmp = pd.DataFrame(
        {"k": host.values, "ts": pd.to_datetime(df["ts"].values, unit="s"), "s": np.asarray(scores, dtype=float)}
    )
    out = np.empty(len(tmp))
    for _, g in tmp.groupby("k", sort=False):
        g = g.sort_values("ts", kind="stable")
        out[g.index.to_numpy()] = g.set_index("ts")["s"].rolling(f"{window_s}s", closed="both").mean().to_numpy()
    return out


def latency_ms(mod, model, df: pd.DataFrame, n: int = 200, seed: int = 0) -> float:
    """Mean wall time to score ONE query (batch of 1), cold, as the live detector would."""
    s = df.sample(min(n, len(df)), random_state=seed)
    mod.score(model, s.iloc[:1])  # warm-up
    t = time.perf_counter()
    for i in range(len(s)):
        mod.score(model, s.iloc[i : i + 1])
    return (time.perf_counter() - t) * 1000 / len(s)


def get_data(a):
    """(train, test, experiment id, run name, split description) from --data or the shared splits."""
    if a.data:
        df = pd.read_parquet(a.data)
        if a.test_data:
            test_df = pd.read_parquet(a.test_data)
            return df, test_df, a.exp, a.exp, f"train={a.data};test={a.test_data}"
        tr, te, desc = split(df)
        return tr, te, a.exp, a.exp, desc
    return get_split(a.exp, Path(a.root), holdout_tool=a.holdout, dataset=a.dataset)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", choices=["m2", "m2sup", "iforest"], required=True)
    ap.add_argument(
        "--exp",
        required=True,
        help=EXP_HELP + ". With the shared splits use E1, E2, E3 (+ --holdout), E4_cic2testbed or E4_testbed2cic",
    )
    ap.add_argument("--data", help="query-table parquet; omit to use the shared split for --exp")
    ap.add_argument("--test-data", help="separate test parquet (with --data)")
    ap.add_argument("--root", default="data/processed", help="folder holding <dataset>/queries.parquet")
    ap.add_argument("--dataset", default="testbed", help="dataset for E3 (testbed or cic)")
    ap.add_argument("--holdout", help="Experiment 3: the tool left out of training")
    ap.add_argument("--tag", default="", help="suffix for ablations, e.g. ablation1_char")
    ap.add_argument("--out", default="results")
    ap.add_argument("--save-model", help="where to save the trained model")
    ap.add_argument(
        "--load-model",
        help="score with this saved model instead of training (benign-only "
        "models: Experiment 3 reuses the Experiment 1 model)",
    )
    ap.add_argument("--init-from", help="M2: continue pre-training from this saved model (e.g. <ckpt>/last)")
    ap.add_argument(
        "--train-time-s",
        type=float,
        help="with --load-model: training time to record (rescoring a model trained in an earlier run)",
    )
    ap.add_argument("--tranco", help="Tranco CSV for extra benign names (M2 only)")
    ap.add_argument("--tranco-n", type=int, default=200_000)
    ap.add_argument("--tokenizer", choices=["bpe", "char"], default="bpe")
    ap.add_argument("--vocab-size", type=int)
    ap.add_argument("--epochs", type=int)
    ap.add_argument("--max-steps", type=int)
    ap.add_argument("--batch-size", type=int)
    ap.add_argument("--lr", type=float)
    ap.add_argument("--ckpt-dir")
    ap.add_argument("--device")
    ap.add_argument("--latency-n", type=int, default=200)
    ap.add_argument(
        "--val-frac",
        type=float,
        default=0.1,
        help="latest share of each capture's benign train rows held out to set the threshold",
    )
    ap.add_argument("--fpr", type=float, default=0.01, help="target false-positive rate for the threshold")
    ap.add_argument(
        "--host-window",
        type=float,
        default=60.0,
        help="per-host averaging window in seconds (also writes <run>_hostavg.json); 0 = off",
    )
    a = ap.parse_args(argv)
    for p in [a.data, a.test_data, a.tranco, a.load_model, a.init_from]:
        if p and not Path(p).exists():
            ap.error(
                f"{p} not found. Build or download it first (README > Quick start), "
                "or see what is missing with: python scripts/check_setup.py data"
            )

    if a.model == "m2sup" and not (a.init_from or a.load_model):
        ap.error("--model m2sup (ablation 2) fine-tunes a saved M2 model: pass --init-from <ckpt>/last")

    train_df, test_df, exp_id, run_name, split_desc = get_data(a)
    if train_df.index.intersection(test_df.index).size:  # two tables (Experiment 4): keep row ids unique
        test_df = test_df.copy()
        test_df.index = test_df.index + int(train_df.index.max()) + 1
    train_df, val_df = hold_out_benign(train_df, a.val_frac)

    if a.model == "m2":
        mod = m2_dnsbert
        cfg = {"tokenizer": a.tokenizer}
        for k in ["vocab_size", "epochs", "max_steps", "batch_size", "lr", "ckpt_dir", "device", "init_from"]:
            if getattr(a, k) is not None:
                cfg[k] = getattr(a, k)
        if a.tranco:
            cfg["extra_benign"] = load_tranco(a.tranco, a.tranco_n)
    elif a.model == "m2sup":
        mod = m2_supervised
        cfg = {k: getattr(a, k) for k in ["epochs", "max_steps", "batch_size", "lr", "device", "init_from"]}
        cfg = {k: v for k, v in cfg.items() if v is not None}
    else:
        mod, cfg = iforest_baseline, {}
        # M1 features computed once on the whole table, so a host's past-only window
        # can reach back across the train/test cut (same as m1_run). The CIC leakage
        # guard inside m1_features drops the snaplen artefacts.
        full = m1_features.attach(pd.concat([train_df, val_df, test_df]))
        train_df, val_df, test_df = full.loc[train_df.index], full.loc[val_df.index], full.loc[test_df.index]

    t0 = time.time()
    if a.load_model:
        model = mod.load(a.load_model, device=a.device) if a.model != "iforest" else mod.load(a.load_model)
        if a.model == "m2" and model.cfg.get("tokenizer") != a.tokenizer:
            ap.error(
                f"--load-model {a.load_model} uses the {model.cfg.get('tokenizer')!r} tokenizer, "
                f"but --tokenizer is {a.tokenizer!r}; pass the matching --tokenizer"
            )
        # reused: its training time is in the run that trained it, unless a rescore passes it on
        train_s = a.train_time_s if a.train_time_s is not None else 0.0
    else:
        model = mod.train(train_df, cfg)
        train_s = time.time() - t0
        if a.model == "m2":  # saved with the model, so runs that --load-model it report it too
            model.cfg["tranco"] = {"path": a.tranco, "n": a.tranco_n} if a.tranco else None
    if a.save_model and not a.load_model:
        mod.save(model, a.save_model)

    t0 = time.time()
    extra = {}
    if a.model == "m2":  # one pass gives both the PPL score and bits per query
        mean_nll, tot_nll = m2_dnsbert._score_both(model, test_df, None)
        scores = mean_nll.astype(np.float32)
        # proposal eq. (1): I(q) = -sum_i log2 P(t_i | q without t_i); grows with name length, unlike the score
        extra["info_bits"] = [round(float(x) / math.log(2), 3) for x in tot_nll]
    else:
        scores = mod.score(model, test_df)
    score_s = time.time() - t0
    lat = latency_ms(mod, model, test_df, a.latency_n)
    val_scores = mod.score(model, val_df) if len(val_df) else np.array([])
    threshold = val_threshold(val_scores, a.fpr) if len(val_df) else None

    used_cfg = model.cfg if hasattr(model, "cfg") else model["cfg"]
    used_cfg = {k: v for k, v in used_cfg.items() if k != "extra_benign"}
    if a.load_model:
        used_cfg["loaded_model"] = a.load_model
    # ablation 2 lives beside the other M2 variants: m2_<tag>, e.g. m2_ablation2_sup
    model_name = ("m2" if a.model == "m2sup" else a.model) + (
        f"_{a.tag}" if a.tag else ("_sup" if a.model == "m2sup" else "")
    )
    base = {
        "model": model_name,
        "experiment": exp_id,
        "dataset": sorted(test_df["dataset"].astype(str).unique().tolist()) if "dataset" in test_df else None,
        "split": split_desc,
        "n_train": int(len(train_df)),
        "n_train_benign": int((train_df["label"] == 0).sum()),
        "n_test": int(len(test_df)),
        "labels": [int(x) for x in test_df["label"]],
        "tools": test_df["tool"].astype(str).tolist() if "tool" in test_df else None,
        "src_hosts": test_df["src_host"].astype(str).tolist() if "src_host" in test_df else None,
        # required by the contract before E3/E5 (docs/contracts.md section 3)
        "session_ids": test_df["session_id"].astype(str).tolist() if "session_id" in test_df else None,
        "ts": [float(x) for x in test_df["ts"]] if "ts" in test_df else None,
        "train_time_s": round(train_s, 3),
        "score_time_s": round(score_s, 3),
        "latency_ms_per_query": round(lat, 3),
        "n_val_benign": int(len(val_df)),
        "config": used_cfg,
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "env": environment(),
    }
    meaning = {
        "m2": "pseudo-log-perplexity (mean masked-token NLL)",
        "m2sup": "supervised fine-tune logit margin (tunnel - benign)",
        "iforest": "negative IsolationForest score_samples",
    }[a.model]
    src = (
        f"validation: latest {a.val_frac:.0%} of each capture's benign train rows, "
        f"eval.metrics.threshold_at_fpr at {a.fpr:.0%} FPR"
    )
    runs = [("", scores, threshold, meaning, extra)]
    if a.host_window > 0:
        hs = host_average(test_df, scores, a.host_window)
        hv = host_average(val_df, val_scores, a.host_window) if len(val_df) else np.array([])
        runs.append(
            (
                "_hostavg",
                hs,
                val_threshold(hv, a.fpr) if len(hv) else None,
                f"{meaning}, mean over the same host's past {a.host_window:g} s",
                {},
            )
        )

    y = np.array(base["labels"])
    for suffix, sc, thr, meaning_i, extra_i in runs:
        res = {
            **base,
            "model": model_name + suffix,
            "scores": [float(x) for x in sc],
            **extra_i,
            "threshold": thr,
            "threshold_source": src,
            "score_meaning": meaning_i,
        }
        if suffix:
            res["config"] = {**used_cfg, "host_window_s": a.host_window}
        # results/<model>/<run>.json: each variant (tag, _hostavg) gets its own model folder, so the
        # eval module groups e.g. E3_iodine for every variant the same way
        out = Path(a.out) / (model_name + suffix) / f"{run_name}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(res))
        # quick sanity print only; real metrics come from the shared eval module
        if 0 < y.sum() < len(y):
            from sklearn.metrics import roc_auc_score

            print(f"[{res['model']}] {run_name} sanity ROC-AUC {roc_auc_score(y, sc):.4f}")
        print(f"[{res['model']}] train {train_s:.1f}s, latency {lat:.2f} ms/query -> {out}")
    return out


if __name__ == "__main__":
    main()
