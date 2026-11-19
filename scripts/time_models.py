"""Time every model on this machine's CPU, on the same test queries, one query at a time.

The 10 ms rule exists for the live detector, which runs on CPU. The per-run latencies in the results
JSONs come from different machines (M1/RF on a Colab CPU, M2/M3 on a Colab T4 GPU), so this script
re-times all models in one process here and writes <results>/latency_cpu.csv, which
`python -m eval.summarise` then uses for the latency table and the selection.

    python scripts/time_models.py                       # defaults below
    python scripts/time_models.py --m2-bpe artifacts/m2_bpe --m2-char artifacts/m2_char

Saved models: M1, RF and M3 from artifacts/<module>/E1.pt (timing does not depend on which experiment
a model was trained for); M2 from the folders saved by m2_dnsbert.save (the shared Drive's
m2/phase2_weights); the Isolation Forest is retrained on the Experiment 1 benign rows (seconds).
A model whose files are missing is skipped with a message.

Checkpoints: each model's row is written to the CSV as soon as it is timed, so a crash loses at most
the model in progress. A rerun skips models already in the CSV; pass --redo to time them again.
Like the per-run timings, a host-averaging variant gets its base model's time.
"""

from __future__ import annotations

import argparse
import importlib
import os
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from eval.experiments import DATA_ROOT, get_split  # noqa: E402
from eval.results_io import environment  # noqa: E402
from eval.run import per_query_latency_ms  # noqa: E402
from models.m1_features import PREFIX  # noqa: E402

# results folder name -> (module, default saved model); None = retrain (Isolation Forest)
MODELS = {
    "m1": ("m1_xgb", "artifacts/m1_xgb/E1.pt"),
    "rf": ("rf_baseline", "artifacts/rf_baseline/E1.pt"),
    "iforest": ("iforest_baseline", None),
    "m2": ("m2_dnsbert", "artifacts/m2_bpe"),
    "m2_ablation1_char": ("m2_dnsbert", "artifacts/m2_char"),
    "m3_cnn": ("m3_cnn", "artifacts/m3_cnn/E1.pt"),
    "m3_bilstm": ("m3_bilstm", "artifacts/m3_bilstm/E1.pt"),
}
SAME_TIME_AS = {"iforest_hostavg": "iforest", "m2_hostavg": "m2", "m2_ablation1_char_hostavg": "m2_ablation1_char"}
COLUMNS = ["model", "latency_ms_per_query", "latency_ms_runs", "n_queries", "cpu", "n_cpus", "timed_utc"]


def load_model(name: str, path: str | None, train_df: pd.DataFrame):
    """(module, model) for one entry of MODELS; None if its saved files are missing."""
    module, _ = MODELS[name]
    mod = importlib.import_module(f"models.{module}")
    if path is None:
        return mod, mod.train(train_df, {})
    if not Path(path).exists():
        return None
    return mod, (mod.load(path, device="cpu") if module == "m2_dnsbert" else mod.load(path))


def write_rows(out: Path, rows: pd.DataFrame) -> None:
    """Write atomically, so a crash mid-write never leaves a half-written checkpoint."""
    tmp = out.with_suffix(".tmp")
    rows[COLUMNS].to_csv(tmp, index=False)
    os.replace(tmp, out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--results-dir", default="results")
    ap.add_argument("--data-root", default=str(DATA_ROOT))
    ap.add_argument("--n", type=int, default=500, help="test queries per timing (default 500)")
    ap.add_argument("--repeats", type=int, default=3, help="timings per model; the median is kept (default 3)")
    ap.add_argument("--m2-bpe", default=MODELS["m2"][1])
    ap.add_argument("--m2-char", default=MODELS["m2_ablation1_char"][1])
    ap.add_argument("--only", nargs="*", choices=list(MODELS), help="time only these models")
    ap.add_argument("--redo", action="store_true", help="time again models already in the CSV")
    a = ap.parse_args(argv)

    paths = {name: path for name, (_, path) in MODELS.items()} | {"m2": a.m2_bpe, "m2_ablation1_char": a.m2_char}
    out = Path(a.results_dir) / "latency_cpu.csv"
    done = pd.read_csv(out) if out.exists() else pd.DataFrame(columns=COLUMNS)  # the checkpoint so far
    todo = [m for m in (a.only or MODELS) if a.redo or m not in set(done["model"])]
    if not todo:
        print(f"all models already in {out}; pass --redo to time them again")
        return 0

    train_df, test_df, *_ = get_split("E1", Path(a.data_root))
    raw = test_df[[c for c in test_df.columns if not c.startswith(PREFIX)]]  # M1/RF compute their features
    queries = raw.sample(min(a.n, len(raw)), random_state=0)
    cpu = environment()["cpu"]
    print(f"timing {', '.join(todo)} on {cpu}, {len(queries)} queries x {a.repeats}")

    for name in todo:
        loaded = load_model(name, paths[name], train_df)
        if loaded is None:
            print(f"[skip] {name}: {paths[name]} not found")
            continue
        mod, model = loaded
        runs = [per_query_latency_ms(mod, model, queries, n=len(queries)) for _ in range(a.repeats)]
        row = {
            "model": name,
            "latency_ms_per_query": statistics.median(runs),
            "latency_ms_runs": " ".join(f"{r:.3f}" for r in runs),
            "n_queries": len(queries),
            "cpu": cpu,
            "n_cpus": os.cpu_count(),
            "timed_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        rows = [row] + [{**row, "model": alias} for alias, base in SAME_TIME_AS.items() if base == name]
        done = pd.concat([done[~done["model"].isin([r["model"] for r in rows])], pd.DataFrame(rows)])
        write_rows(out, done.sort_values("model"))
        print(f"[ ok ] {name}: {row['latency_ms_per_query']:.2f} ms/query (runs {row['latency_ms_runs']}) -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
