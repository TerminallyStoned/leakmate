"""Experiment 5 (low-and-slow) for M2 and the Isolation Forest, derived from the Experiment 1 results.

Both models train on benign rows only, and Experiment 5 only drops tunnel rows from training
(eval.experiments.get_split), so its model, validation rows and thresholds are exactly the
Experiment 1 ones. Experiment 5 is therefore Experiment 1's test set filtered to benign rows plus
the low-and-slow tunnel rows (throttle >= LOW_AND_SLOW_MS); host averaging is recomputed on the
kept rows, as a direct `m2_run --exp E5` would. No GPU, no retraining.

    python scripts/m2_e5.py --results results --manifest data/raw/manifest.csv \
        --models m2 m2_ablation1_char iforest

Writes <results>/<model>/E5.json and <results>/<model>_hostavg/E5.json.
For the Isolation Forest the per-host features stay those computed on the whole table (as in
Experiment 1), so its derived scores can differ slightly from a direct E5 run, which would
recompute the host windows without the fast tunnel rows.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from eval.experiments import LOW_AND_SLOW_MS  # noqa: E402
from models.m2_run import host_average  # noqa: E402

PER_ROW = ["scores", "labels", "tools", "src_hosts", "session_ids", "ts", "info_bits"]
SPLIT_NOTE = f";train throttle<{LOW_AND_SLOW_MS}ms;test throttle>={LOW_AND_SLOW_MS}ms"


def row_throttle(session_ids: list[str], labels: list[int], manifest_csv: Path) -> list[int]:
    """Configured throttle (ms) per row from the manifest (by capture file); 0 for benign or unknown files."""
    man = pd.read_csv(manifest_csv)
    by_file = dict(zip(man["file"].astype(str), pd.to_numeric(man["throttle_ms"], errors="coerce").fillna(0)))
    return [int(by_file.get(s.split("|")[0], 0)) if lab else 0 for s, lab in zip(session_ids, labels)]


def _filter(res: dict, keep: list[bool]) -> dict:
    out = {**res}
    for k in PER_ROW:
        if out.get(k) is not None:
            out[k] = [v for v, ok in zip(out[k], keep) if ok]
    out["experiment"] = "E5"
    out["n_test"] = sum(keep)
    out["split"] = str(res.get("split", "")) + SPLIT_NOTE
    out["config"] = {**(res.get("config") or {}), "derived_from": "E1"}
    return out


def derive_e5(
    e1: dict, throttle: list[int], e1_hostavg: dict | None = None, host_window_s: float = 60.0
) -> tuple[dict, dict | None]:
    """(per-query E5 result, host-averaged E5 result or None) from Experiment 1 results."""
    if len(throttle) != e1["n_test"]:
        raise ValueError(f"throttle has {len(throttle)} rows, E1 has {e1['n_test']}")
    keep = [lab == 0 or th >= LOW_AND_SLOW_MS for lab, th in zip(e1["labels"], throttle)]
    e5 = _filter(e1, keep)
    if e1_hostavg is None:
        return e5, None
    df = pd.DataFrame(
        {
            "src_host": e5["src_hosts"],
            "ts": e5["ts"],
            "source_file": [s.split("|")[0] for s in e5["session_ids"]],
        }
    )
    e5h = _filter(e1_hostavg, keep)
    e5h["scores"] = [float(x) for x in host_average(df, e5["scores"], host_window_s)]
    e5h["threshold"] = e1_hostavg["threshold"]
    return e5, e5h


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--results", default="results", help="folder holding <model>/E1.json")
    ap.add_argument("--manifest", default="data/raw/manifest.csv")
    ap.add_argument("--models", nargs="+", default=["m2", "m2_ablation1_char", "iforest"])
    a = ap.parse_args(argv)
    root = Path(a.results)
    for model in a.models:
        e1 = json.loads((root / model / "E1.json").read_text())
        hpath = root / f"{model}_hostavg" / "E1.json"
        e1h = json.loads(hpath.read_text()) if hpath.exists() else None
        window = float((e1h or {}).get("config", {}).get("host_window_s", 60.0))
        throttle = row_throttle(e1["session_ids"], e1["labels"], Path(a.manifest))
        for res in derive_e5(e1, throttle, e1h, window):
            if res is None:
                continue
            out = root / res["model"] / "E5.json"
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(res))
            print(f"[{res['model']}] E5: {res['n_test']} rows ({sum(res['labels'])} slow tunnel) -> {out}")


if __name__ == "__main__":
    main()
