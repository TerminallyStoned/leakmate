"""Turn every results JSON into one CSV, figures and the model selection.

    python -m eval.summarise                 # reads results/, writes results/summary.csv etc.
    python -m eval.summarise --results-dir results --no-plots
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path

import pandas as pd

from eval.results_io import iter_results
from eval.metrics import MAX_LATENCY_MS, evaluate_run, per_tool_recall, select_model
from eval.plots import plot_confusion, plot_latency, plot_roc

COLUMNS = ["model", "experiment", "n", "n_tunnel", "threshold", "threshold_source",
           "accuracy", "precision", "recall", "f1", "fpr", "roc_auc",
           "recall_at_1pct_fpr", "train_time_s", "latency_ms_per_query", "tp", "fp", "tn", "fn"]


def latency_table(summary: pd.DataFrame, limit_ms: float = MAX_LATENCY_MS) -> pd.DataFrame:
    """One row per model: per-query latency across its runs and whether it meets the limit.

    Numbers come from each results JSON's `latency_ms_per_query`. Runs on different machines are
    not comparable; the official table uses Kang Hao Wei's single-machine re-timing,
    which only needs to write results JSONs with the new latency_ms_per_query to update this."""
    g = summary.dropna(subset=["latency_ms_per_query"]).groupby("model")
    table = pd.DataFrame({
        "latency_ms_median": g["latency_ms_per_query"].median(),
        "latency_ms_min": g["latency_ms_per_query"].min(),
        "latency_ms_max": g["latency_ms_per_query"].max(),
        "queries_per_sec": 1000 / g["latency_ms_per_query"].median(),
        "train_time_s_median": g["train_time_s"].median(),
        "n_runs": g.size(),
    }).reset_index()
    table["under_limit"] = table["latency_ms_max"] < limit_ms
    return table.sort_values("latency_ms_median").round(4)


def summarise(results_dir: str = "results", plots: bool = True) -> pd.DataFrame:
    results_dir = Path(results_dir)
    fig_dir = results_dir / "figures"
    fig_dir.mkdir(parents=True, exist_ok=True)

    rows, tool_rows = [], []
    by_exp: dict[str, dict[str, dict]] = defaultdict(dict)
    for model, exp, run in iter_results(results_dir):
        m = evaluate_run(run)
        rows.append({"model": model, "experiment": exp, **m})
        by_exp[exp][model] = run
        if run.get("tools") is not None:
            for tool, rec in per_tool_recall(run["labels"], run["scores"],
                                             run["tools"], m["threshold"]).items():
                tool_rows.append({"model": model, "experiment": exp,
                                  "tool": tool, "recall": rec})
        if plots:
            plot_confusion(m, model, exp, fig_dir)

    if not rows:
        raise SystemExit(f"No results found under {results_dir}/<model>/<exp>.json")

    summary = pd.DataFrame(rows)[COLUMNS].sort_values(["experiment", "model"])
    summary.to_csv(results_dir / "summary.csv", index=False)
    if tool_rows:
        pd.DataFrame(tool_rows).to_csv(results_dir / "per_tool.csv", index=False)

    latency = latency_table(summary)
    latency.to_csv(results_dir / "latency.csv", index=False)

    if plots:
        for exp, runs in by_exp.items():
            plot_roc(runs, exp, fig_dir)
        plot_latency(latency, fig_dir, MAX_LATENCY_MS)

    # Selection rule, applied separately to each experiment.
    picks = []
    for exp, grp in summary.groupby("experiment"):
        win = select_model(grp.to_dict("records"))
        picks.append({"experiment": exp,
                      "selected_model": win["model"] if win else None,
                      "f1": win["f1"] if win else None,
                      "fpr": win["fpr"] if win else None,
                      "latency_ms_per_query": win["latency_ms_per_query"] if win else None})
    pd.DataFrame(picks).to_csv(results_dir / "selection.csv", index=False)
    return summary


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--results-dir", default="results")
    ap.add_argument("--no-plots", action="store_true")
    args = ap.parse_args()
    summary = summarise(args.results_dir, plots=not args.no_plots)
    with pd.option_context("display.width", 160, "display.max_columns", 20):
        print(summary[["model", "experiment", "precision", "recall", "f1", "fpr",
                       "roc_auc", "latency_ms_per_query", "threshold_source"]].round(4))
    print("\nLatency per model:")
    print(pd.read_csv(Path(args.results_dir) / "latency.csv")
          [["model", "latency_ms_median", "queries_per_sec", "under_limit"]].to_string(index=False))
    print(f"\nWrote {args.results_dir}/summary.csv, latency.csv, selection.csv and figures/")


if __name__ == "__main__":
    main()
