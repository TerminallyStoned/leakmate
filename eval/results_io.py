"""Reading and writing results/<model>/<experiment>.json (format from the CONTRACTS card)."""

from __future__ import annotations

import json
import platform
import sys
from importlib import metadata
from pathlib import Path

import numpy as np

from scripts.check_setup import GROUPS, requirements


def environment() -> dict:
    """Where a run happened: Python and library versions, the CPU, and the GPU torch can see (None if torch
    was not imported or there is no GPU; a CPU-only run on a GPU machine still lists the GPU).

    The versions are those of every package in the requirements files (scripts/check_setup.py GROUPS) that
    is installed here. A threshold can sit in a dense band of scores, so a small numeric difference between
    machines moves many rows across it (issue #35)."""
    names = {name for req_file, _ in GROUPS.values() if req_file for name, _ in requirements(req_file)}
    versions = {}
    for pkg in sorted(names):
        try:
            versions[pkg] = metadata.version(pkg)
        except metadata.PackageNotFoundError:
            pass
    cpu = platform.processor()
    try:  # Linux and Colab leave platform.processor() empty or vague
        lines = Path("/proc/cpuinfo").read_text().splitlines()
        cpu = next(ln.split(":", 1)[1].strip() for ln in lines if ln.startswith("model name"))
    except (OSError, StopIteration):
        pass
    torch = sys.modules.get("torch")  # only if this run already imported it
    gpu = torch.cuda.get_device_name(0) if torch is not None and torch.cuda.is_available() else None
    return {"python": platform.python_version(), "packages": versions, "cpu": cpu or platform.machine(), "gpu": gpu}


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
        "env": environment(),
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
