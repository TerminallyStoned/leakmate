"""Turn DNS captures into the contract query table (docs/contracts.md), its features and splits.

    from parser import load
    train, test = load("cic")          # data/processed/cic/queries.parquet, time-based split

CLI: `python -m parser --help`.
"""

from __future__ import annotations

from pathlib import Path

from eval.experiments import DATA_ROOT, default_split, load_queries


def load(dataset: str = "cic", root: str | Path = DATA_ROOT):
    """(train, test) query tables for one dataset, split by time/session, never shuffled rows.

    Uses the table's own `split` column when it has one (CIC), else earliest 70% of sessions
    per class -> train. Same rule as eval.experiments, which the experiments use."""
    train, test, _ = default_split(load_queries(dataset, Path(root)))
    return train, test
