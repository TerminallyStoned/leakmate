"""Reading and writing results/<model>/<experiment>.json (format from the CONTRACTS card)."""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np

# Field names exactly as used by the results files on main.
REQUIRED = ("scores", "labels", "train_time_s", "latency_ms_per_query", "config")

# Older or alternative names -> the name above. Add a line here if a teammate's
# results file uses a different spelling; nothing else needs to change.
ALIASES = {
    "latency_ms": "latency_ms_per_query",
}


def write_result(path: str | Path, scores, labels, train_time_s: float,
                 latency_ms_per_query: float, config: dict, **extra) -> Path:
    """Write one run. `extra` may hold optional fields: threshold, tools, qnames."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    run = {
        "scores": np.asarray(scores, dtype=float).round(6).tolist(),
        "labels": np.asarray(labels, dtype=int).tolist(),
        "train_time_s": float(train_time_s),
        "latency_ms_per_query": float(latency_ms_per_query),
        "config": config,
    }
    for k, v in extra.items():
        run[k] = v.tolist() if isinstance(v, np.ndarray) else v
    path.write_text(json.dumps(run))
    return path


def load_result(path: str | Path) -> dict:
    run = json.loads(Path(path).read_text())
    for old, new in ALIASES.items():
        if old in run and new not in run:
            run[new] = run.pop(old)
    missing = [k for k in REQUIRED if k not in run]
    if missing:
        raise ValueError(f"{path}: missing fields {missing} (found {sorted(run)})")
    if len(run["scores"]) != len(run["labels"]):
        raise ValueError(f"{path}: scores and labels differ in length")
    return run


def iter_results(results_dir: str | Path = "results"):
    """Yield (model, experiment, run) for every results/<model>/<exp>.json."""
    for path in sorted(Path(results_dir).glob("*/*.json")):
        if path.parent.name in ("figures",):
            continue
        yield path.parent.name, path.stem, load_result(path)
