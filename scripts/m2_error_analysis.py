"""Error analysis for M2 runs: which benign names are false alarms, and which tunnels are missed.

Joins each results JSON back to its query names by rebuilding the test split from the query
table (eval.experiments.get_split), and refuses to run if the rows do not line up. Errors are
judged at the run's own threshold (score >= threshold = flagged), as the eval module does.

    python scripts/m2_error_analysis.py --root data/processed_nozone --results nz/results \
        --runs m2/E1 m2_hostavg/E1 m2/E5 m2_ablation2_sup/E1 --out m2_errors_masked.md
    python scripts/m2_error_analysis.py --root data/processed --results results \
        --runs m2/E4_cic2testbed m2/E4_testbed2cic --out m2_errors_e4.md

Prints Markdown tables (and writes them to --out); the metrics themselves come from eval/.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from eval.experiments import get_split  # noqa: E402

LENGTH_BINS = [0, 30, 60, 100, 150, 200, np.inf]
LENGTH_LABELS = ["≤30", "31–60", "61–100", "101–150", "151–200", ">200"]


def align(result: dict, test_df: pd.DataFrame) -> pd.DataFrame:
    """test_df plus score, flagged and error ("FP", "FN" or None); raises if the rows differ from the result's."""
    df = test_df.reset_index(drop=True)
    checks = {
        "n_test": result["n_test"] == len(df),
        "labels": result["n_test"] == len(df) and list(result["labels"]) == df["label"].astype(int).tolist(),
        "session_ids": result.get("session_ids") is None
        or (result["n_test"] == len(df) and list(result["session_ids"]) == df["session_id"].astype(str).tolist()),
        "ts": result.get("ts") is None
        or (result["n_test"] == len(df) and np.allclose(result["ts"], df["ts"].astype(float), rtol=0, atol=1e-6)),
    }
    for field, ok in checks.items():
        if not ok:
            raise ValueError(f"result does not match this table: {field} (wrong --root, masked vs original?)")
    out = df.copy()
    out["score"] = np.asarray(result["scores"], dtype=float)
    out["flagged"] = out["score"] >= float(result["threshold"])
    out["error"] = None
    out.loc[out["flagged"] & (out["label"] == 0), "error"] = "FP"
    out.loc[~out["flagged"] & (out["label"] == 1), "error"] = "FN"
    return out


def summarise_errors(aligned: pd.DataFrame, top: int = 15) -> dict[str, pd.DataFrame]:
    """Tables for the report: fp_by_name, fp_by_domain, fn_by_tool, fn_by_length, fn_examples."""
    fp = aligned[aligned["error"] == "FP"]
    tun = aligned[aligned["label"] == 1].assign(
        missed=lambda d: d["error"] == "FN", length=lambda d: d["qname"].str.len()
    )
    fp_by_name = (
        fp.groupby("qname")
        .agg(count=("score", "size"), max_score=("score", "max"))
        .sort_values(["count", "max_score"], ascending=False)
        .head(top)
        .reset_index()
    )
    fp_by_domain = (
        fp.assign(domain=fp["qname"].map(lambda q: ".".join([x for x in str(q).rstrip(".").split(".") if x][-2:])))
        .groupby("domain")
        .agg(count=("qname", "size"), distinct_names=("qname", "nunique"))
        .sort_values("count", ascending=False)
        .head(top)
        .reset_index()
    )
    by_tool = tun.groupby("tool").agg(rows=("missed", "size"), missed=("missed", "sum")).reset_index()
    by_tool["recall"] = 1 - by_tool["missed"] / by_tool["rows"]
    bins = pd.cut(tun["length"], LENGTH_BINS, labels=LENGTH_LABELS)
    by_len = (
        tun.groupby(bins, observed=False)
        .agg(rows=("missed", "size"), missed=("missed", "sum"))
        .rename_axis("length")
        .reset_index()
    )
    by_len["length"] = by_len["length"].astype(str)
    by_len["recall"] = np.where(by_len["rows"] > 0, 1 - by_len["missed"] / by_len["rows"].clip(lower=1), np.nan)
    ex = tun[tun["missed"]].sort_values("score").groupby("tool").head(3)[["tool", "qname", "length", "score"]]
    return {
        "fp_by_name": fp_by_name,
        "fp_by_domain": fp_by_domain,
        "fn_by_tool": by_tool,
        "fn_by_length": by_len,
        "fn_examples": ex.reset_index(drop=True),
    }


def _md(df: pd.DataFrame) -> str:
    if df.empty:
        return "_none_\n"

    def cell(v):
        if isinstance(v, float | np.floating):
            return "" if np.isnan(v) else f"{v:.3f}"
        return str(v).replace("|", "\\|")

    lines = ["| " + " | ".join(df.columns) + " |", "|" + "---|" * len(df.columns)]
    lines += ["| " + " | ".join(cell(v) for v in row) + " |" for row in df.itertuples(index=False)]
    return "\n".join(lines) + "\n"


def _split_for(run: str, root: Path) -> pd.DataFrame:
    """Rebuild the test rows a run was scored on (same rule as models.m2_run without --data)."""
    if run.startswith("E3_"):
        return get_split("E3", root, holdout_tool=run[3:])[1]
    return get_split(run, root)[1]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--root", required=True, help="query-table root the runs were scored on")
    ap.add_argument("--results", required=True, help="folder holding <model>/<run>.json")
    ap.add_argument("--runs", nargs="+", required=True, help="<model>/<run>, e.g. m2/E1 m2_hostavg/E5")
    ap.add_argument("--top", type=int, default=15)
    ap.add_argument("--out", help="also write the Markdown here")
    a = ap.parse_args(argv)
    parts = [f"# M2 error analysis (`--root {a.root}`)\n"]
    for spec in a.runs:
        model, run = spec.split("/")
        res = json.loads((Path(a.results) / model / f"{run}.json").read_text())
        s = summarise_errors(align(res, _split_for(run, Path(a.root))), a.top)
        n_fp = int(s["fp_by_domain"]["count"].sum()) if len(s["fp_by_domain"]) else 0
        parts.append(f"## {model} / {run}\n")
        parts.append(
            f"Threshold {res['threshold']:.4f}; missed tunnels {int(s['fn_by_tool']['missed'].sum())} "
            f"of {int(s['fn_by_tool']['rows'].sum())}; false positives in the top {a.top} domains: {n_fp}.\n"
        )
        for name, table in s.items():
            parts.append(f"### {name}\n\n{_md(table)}")
    text = "\n".join(parts)
    print(text)
    if a.out:
        Path(a.out).write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
