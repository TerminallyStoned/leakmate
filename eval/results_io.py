"""Reading and writing results/<model>/<experiment>.json (format from the CONTRACTS card)."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np

# The fields the evaluation module itself needs. The full contract (docs/contracts.md
# section 3) requires more; writers check that with contracts.py (write_result(validate=True)).
REQUIRED = ("scores", "labels", "train_time_s", "latency_ms_per_query")

# Older or alternative names -> the name above. Add a line here if a teammate's
# results file uses a different spelling; nothing else needs to change.
ALIASES = {
    "latency_ms": "latency_ms_per_query",
}


def write_result(
    path: str | Path,
    scores,
    labels,
    train_time_s: float,
    latency_ms_per_query: float,
    config: dict,
    validate: bool = False,
    **extra,
) -> Path:
    """Write one run. `extra` holds the other contract keys (model, experiment, dataset,
    split, n_train, n_test, tools, src_hosts, score_meaning, created_utc, ...) and any
    extra keys such as threshold.

    validate=True checks the record with the team's contracts.py first and refuses to
    write a file that breaks the contract (ContractError lists every problem)."""
    path = Path(path)
    run = {
        "scores": np.asarray(scores, dtype=float).round(6).tolist(),
        "labels": np.asarray(labels, dtype=int).tolist(),
        "train_time_s": float(train_time_s),
        "latency_ms_per_query": float(latency_ms_per_query),
        "config": config,
    }
    for k, v in extra.items():
        if v is None:
            continue
        run[k] = v.tolist() if isinstance(v, np.ndarray) else v
    if validate:
        from contracts import validate as validate_contract  # repo root

        validate_contract(run)
    path.parent.mkdir(parents=True, exist_ok=True)
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


def run_identity(folder: str, stem: str, run: dict) -> tuple[str, str, bool]:
    """(model, group, is_ablation) for one results file.

    Uses the file's own `model` and `experiment` keys (contract section 3), falling back
    to the folder and file name. `group` is the experiment plus any run tag that is not
    already part of the model name, e.g.
      results/m3_cnn/E3_iodine.json  model m3_cnn,                 group E3_iodine
      results/m1/E2_ablation_x.json  model m1_ablation_x (in JSON), group E2
    """
    model = run.get("model", folder)
    exp = run.get("experiment", stem)
    tag = stem[len(exp) :].lstrip("_") if stem.startswith(exp) else ""
    if tag and model.endswith(tag):
        tag = ""
    return model, f"{exp}_{tag}" if tag else exp, "ablation" in model


def iter_results(results_dir: str | Path = "results"):
    """Yield (folder, file stem, run) for every results/<folder>/<run>.json.
    Deeper files (e.g. results/m1/shap/*.json) and results/figures are skipped."""
    for path in sorted(Path(results_dir).glob("*/*.json")):
        if path.parent.name in ("figures",):
            continue
        yield path.parent.name, path.stem, load_result(path)
