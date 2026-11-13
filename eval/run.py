"""Train a model on one experiment's split, score the test set, write the results JSON.

    python -m eval.run --model m3 --exp E2                # m3 = both m3_cnn and m3_bilstm
    python -m eval.run --model m3_cnn --exp E3 --holdout iodine
    python -m eval.run --model m3 --exp E2 --epochs 1 --max-rows 20000   # quick smoke test

Every model is a module models/<name>.py with
    train(train_df, cfg) -> model
    score(model, df) -> np.ndarray      (higher = more suspicious)
    save(model, path) / load(path)
A model may also expose `model.threshold` (chosen on its own validation split); it is
saved in the JSON so the evaluation module does not have to pick a threshold on test data.
"""
from __future__ import annotations

import argparse
import importlib
import time
from pathlib import Path

import pandas as pd

from eval.experiments import DATA_ROOT, get_split
from eval.results_io import write_result

ALIASES = {"m3": ["m3_cnn", "m3_bilstm"]}


def per_query_latency_ms(mod, model, df, n: int = 1000) -> float:
    """Rough per-query latency: score n queries one at a time on the current device.
    The official cross-model latency table is run separately on one fixed machine."""
    sample = df.head(n)
    if sample.empty:
        return float("nan")
    mod.score(model, sample.head(1))  # warm-up
    t0 = time.perf_counter()
    for i in range(len(sample)):
        mod.score(model, sample.iloc[i:i + 1])
    return (time.perf_counter() - t0) * 1000 / len(sample)


def _subsample(df, max_rows: int):
    """Up to max_rows/2 rows per class, kept in time order."""
    parts = [g.sample(min(len(g), max_rows // 2), random_state=0)
             for _, g in df.groupby("label")]
    return pd.concat(parts).sort_values("ts")


def run_one(model_name: str, exp: str, cfg: dict, holdout: str | None,
            data_root: Path, results_dir: Path, max_rows: int | None,
            dataset: str = "testbed") -> Path:
    mod = importlib.import_module(f"models.{model_name}")
    train_df, test_df, result_name = get_split(exp, data_root, holdout_tool=holdout,
                                               dataset=dataset)
    if max_rows:  # keep both classes when subsampling for smoke tests
        train_df, test_df = (_subsample(train_df, max_rows), _subsample(test_df, max_rows))
    print(f"[{model_name} {result_name}] train={len(train_df):,} test={len(test_df):,}")

    t0 = time.perf_counter()
    model = mod.train(train_df, cfg)
    train_time = time.perf_counter() - t0

    scores = mod.score(model, test_df)
    latency = per_query_latency_ms(mod, model, test_df, n=cfg.get("latency_n", 500))

    model_path = Path("artifacts") / model_name / f"{result_name}.pt"
    mod.save(model, model_path)

    out = write_result(
        results_dir / model_name / f"{result_name}.json",
        scores=scores, labels=test_df["label"].to_numpy(),
        train_time_s=train_time, latency_ms_per_query=latency,
        config={**getattr(model, "cfg", cfg), "experiment": result_name,
                "dataset": dataset if exp in ("E3", "S", "S_shuffled") else None},
        threshold=getattr(model, "threshold", None),
        tools=test_df["tool"].astype(str).to_numpy(),
    )
    print(f"[{model_name} {result_name}] train {train_time:.1f}s, "
          f"latency {latency:.2f} ms/query -> {out}")
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", required=True, help="m3, m3_cnn, m3_bilstm, ...")
    ap.add_argument("--exp", required=True,
                    help="E1 E2 E3 E4_cic2testbed E4_testbed2cic E5 S")
    ap.add_argument("--holdout", help="tool to hold out for E3 (all tools if omitted)")
    ap.add_argument("--dataset", default="testbed", choices=["testbed", "cic"],
                    help="dataset for E3 and S (default testbed; use cic before testbed data exists)")
    ap.add_argument("--epochs", type=int)
    ap.add_argument("--batch-size", type=int)
    ap.add_argument("--max-rows", type=int, help="subsample for quick tests")
    ap.add_argument("--data-root", default=str(DATA_ROOT))
    ap.add_argument("--results-dir", default="results")
    args = ap.parse_args()

    cfg = {k: v for k, v in {"epochs": args.epochs,
                             "batch_size": args.batch_size}.items() if v is not None}
    models = ALIASES.get(args.model, [args.model])
    data_root, results_dir = Path(args.data_root), Path(args.results_dir)

    holdouts = [args.holdout]
    if args.exp == "E3" and not args.holdout:
        from eval.experiments import tools_in
        holdouts = tools_in(args.dataset, data_root)

    for name in models:
        for h in holdouts:
            run_one(name, args.exp, dict(cfg), h, data_root, results_dir, args.max_rows,
                    dataset=args.dataset)


if __name__ == "__main__":
    main()
