"""Train a model on one experiment's split, score the test set, write the results JSON.

    python -m eval.run --model m3 --exp E2                # m3 = both m3_cnn and m3_bilstm
    python -m eval.run --model m3_cnn --exp E3 --holdout iodine
    python -m eval.run --model m3 --exp E2 --epochs 1 --max-rows 20000   # quick smoke test
    python -m eval.run --model m3 --exp E2 --dataset synthetic --epochs 1  # contract sample

Each results file follows docs/contracts.md section 3 and is checked with contracts.py
before it is written.

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
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from eval.experiments import DATA_ROOT, EXP_HELP, get_split
from eval.results_io import write_result

ALIASES = {"m3": ["m3_cnn", "m3_bilstm"], "m1": ["m1_xgb"], "rf": ["rf_baseline"], "iforest": ["iforest_baseline"]}
# results/<name>/ folder and `model` key per module, matching what models/m1_run.py and m2_run.py write
RESULT_DIRS = {"m1_xgb": "m1", "rf_baseline": "rf", "iforest_baseline": "iforest"}
SCORE_MEANING = {
    "m1": "XGBoost P(tunnel)",
    "rf": "RandomForest P(tunnel)",
    "iforest": "negative IsolationForest score_samples",
}


def per_query_latency_ms(mod, model, df, n: int = 1000) -> float:
    """Rough per-query latency: score n queries one at a time on the current device.
    The official cross-model latency table is run separately on one fixed machine."""
    sample = df.head(n)
    if sample.empty:
        return float("nan")
    mod.score(model, sample.head(1))  # warm-up
    t0 = time.perf_counter()
    for i in range(len(sample)):
        mod.score(model, sample.iloc[i : i + 1])
    return (time.perf_counter() - t0) * 1000 / len(sample)


def _subsample(df, max_rows: int):
    """Up to max_rows/2 rows per class, kept in time order."""
    parts = [g.sample(min(len(g), max_rows // 2), random_state=0) for _, g in df.groupby("label")]
    return pd.concat(parts).sort_values("ts")


def run_one(
    model_name: str,
    exp: str,
    cfg: dict,
    holdout: str | None,
    data_root: Path,
    results_dir: Path,
    max_rows: int | None,
    dataset: str = "testbed",
    overwrite: bool = False,
) -> Path:
    mod = importlib.import_module(f"models.{model_name}")
    train_df, test_df, exp_id, run_name, split_desc = get_split(exp, data_root, holdout_tool=holdout, dataset=dataset)
    model_dir = RESULT_DIRS.get(model_name, model_name)
    out_path = results_dir / model_dir / f"{run_name}.json"
    if out_path.exists() and not overwrite:
        # models/m1_run.py and m2_run.py write to the same folders with their own splits
        raise SystemExit(
            f"{out_path} already exists (maybe from models.m1_run / m2_run); "
            "pass --overwrite to replace it, or --results-dir to write elsewhere"
        )
    if max_rows:  # keep both classes when subsampling for smoke tests
        train_df, test_df = (_subsample(train_df, max_rows), _subsample(test_df, max_rows))
        split_desc += f";max_rows={max_rows}"
    print(f"[{model_name} {run_name}] train={len(train_df):,} test={len(test_df):,}")

    t0 = time.perf_counter()
    model = mod.train(train_df, cfg)
    train_time = time.perf_counter() - t0

    scores = mod.score(model, test_df)
    latency = per_query_latency_ms(mod, model, test_df, n=cfg.get("latency_n", 500))

    mod.save(model, Path("artifacts") / model_name / f"{run_name}.pt")

    # Every key the contract (docs/contracts.md section 3) requires, plus optional extras.
    # M3 models carry .cfg; M1/RF/IF models are dicts with a "cfg" key
    used_cfg = model.get("cfg", cfg) if isinstance(model, dict) else getattr(model, "cfg", cfg)
    out = write_result(
        out_path,
        scores=scores,
        labels=test_df["label"].to_numpy(),
        train_time_s=train_time,
        latency_ms_per_query=latency,
        config={**used_cfg, "max_rows": max_rows},
        model=model_dir,
        experiment=exp_id,
        dataset=sorted(test_df["dataset"].astype(str).unique()),
        split=split_desc,
        n_train=len(train_df),
        n_test=len(test_df),
        tools=test_df["tool"].astype(str).to_numpy(),
        src_hosts=test_df["src_host"].astype(str).to_numpy(),
        session_ids=test_df["session_id"].astype(str).to_numpy(),
        ts=test_df["ts"].astype(float).to_numpy(),
        score_meaning=SCORE_MEANING.get(
            model_dir, getattr(mod, "SCORE_MEANING", f"{model_name} score, higher = more suspicious")
        ),
        created_utc=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        threshold=getattr(model, "threshold", None),  # extra key: chosen on validation data
        validate=True,
    )
    print(f"[{model_name} {run_name}] train {train_time:.1f}s, latency {latency:.2f} ms/query -> {out}")
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument(
        "--model",
        required=True,
        help="m1, rf, iforest, m3 (= m3_cnn + m3_bilstm), or any models/<name>.py. "
        "M2 runs through python -m models.m2_run (needs the Tranco list)",
    )
    ap.add_argument("--exp", required=True, help=EXP_HELP + " (Experiment 4 takes E4_cic2testbed or E4_testbed2cic)")
    ap.add_argument("--holdout", help="tool to hold out in Experiment 3, leave-one-tool-out (all tools if omitted)")
    ap.add_argument(
        "--dataset",
        default="testbed",
        choices=["testbed", "cic", "synthetic"],
        help="dataset for E3 and S (default testbed; use cic before testbed data "
        "exists). 'synthetic' runs any experiment on the contract sample.",
    )
    ap.add_argument("--epochs", type=int)
    ap.add_argument("--batch-size", type=int)
    ap.add_argument("--max-rows", type=int, help="subsample for quick tests")
    ap.add_argument("--data-root", default=str(DATA_ROOT))
    ap.add_argument("--results-dir", default="results")
    ap.add_argument("--overwrite", action="store_true", help="replace an existing results file")
    args = ap.parse_args()

    cfg = {k: v for k, v in {"epochs": args.epochs, "batch_size": args.batch_size}.items() if v is not None}
    models = ALIASES.get(args.model, [args.model])
    data_root, results_dir = Path(args.data_root), Path(args.results_dir)

    holdouts = [args.holdout]
    if args.exp == "E3" and not args.holdout:
        from eval.experiments import tools_in

        holdouts = tools_in(args.dataset, data_root)

    for name in models:
        for h in holdouts:
            run_one(
                name,
                args.exp,
                dict(cfg),
                h,
                data_root,
                results_dir,
                args.max_rows,
                dataset=args.dataset,
                overwrite=args.overwrite,
            )


if __name__ == "__main__":
    main()
