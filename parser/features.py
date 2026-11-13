"""Query table -> features.parquet: per-query and per-host window features, one row per query.

    python -m parser features --dataset cic    # data/processed/cic/{queries -> features}.parquet

Rows line up with queries.parquet (same order). The features are the ones M1 and the Random
Forest train on (models/m1_features.py), computed over the whole table as models/m1_run.py
does; host windows only look back in time, so this leaks nothing across the split.
CIC's snaplen-affected columns are kept here; models drop them with m1_features.drop_list,
which needs the `qname_truncated` column, so it is carried over from the query table.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from models import m1_features

KEYS = ["ts", "src_host", "session_id", "label", "tool", "split", "qname_truncated"]


def build(queries: pd.DataFrame) -> pd.DataFrame:
    keys = queries[[c for c in KEYS if c in queries.columns]]
    return keys.join(m1_features.build(queries))


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="python -m parser features")
    ap.add_argument("--dataset", default="cic")
    ap.add_argument("--root", default="data/processed")
    a = ap.parse_args(argv)
    folder = Path(a.root) / a.dataset
    feats = build(pd.read_parquet(folder / "queries.parquet"))
    feats.to_parquet(folder / "features.parquet", index=False)
    print(f"-> {folder / 'features.parquet'}: {len(feats)} rows x {len(feats.columns.difference(KEYS))} features")


if __name__ == "__main__":
    main()
