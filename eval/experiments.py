"""Train/test splits for each experiment ID (E1-E5, S) from the CONTRACTS card.

PLACEHOLDER: Yehan owns the official splits ("Parser + features + splits" card).
When his version lands, make `get_split` call it and delete the logic below.
Everything here only relies on the query-table schema, so swapping is one import.

Splits are by SESSION and TIME, never by shuffled rows (except experiment S).
"""
from __future__ import annotations

from pathlib import Path

import pandas as pd

DATA_ROOT = Path("data/processed")
TRAIN_FRAC = 0.7


def load_queries(dataset: str, root: Path = DATA_ROOT) -> pd.DataFrame:
    df = pd.read_parquet(root / dataset / "queries.parquet")
    return df.sort_values("ts").reset_index(drop=True)


def time_session_split(df: pd.DataFrame, train_frac: float = TRAIN_FRAC):
    """Earliest sessions go to train, later sessions to test, done per label so
    both sides contain benign and tunnel traffic. A session never straddles the cut."""
    train_parts, test_parts = [], []
    for _, part in df.groupby("label"):
        starts = part.groupby("session_id")["ts"].min().sort_values()
        cut = max(1, int(len(starts) * train_frac))
        train_ids = set(starts.index[:cut])
        in_train = part["session_id"].isin(train_ids)
        train_parts.append(part[in_train])
        test_parts.append(part[~in_train])
    return (pd.concat(train_parts).sort_values("ts"),
            pd.concat(test_parts).sort_values("ts"))


def shuffled_split(df: pd.DataFrame, train_frac: float = TRAIN_FRAC, seed: int = 0):
    """The WRONG way (rows shuffled). Only used by experiment S to show the inflation."""
    shuf = df.sample(frac=1.0, random_state=seed)
    cut = int(len(shuf) * train_frac)
    return shuf.iloc[:cut], shuf.iloc[cut:]


def tools_in(dataset: str, root: Path = DATA_ROOT) -> list[str]:
    df = load_queries(dataset, root)
    return sorted(t for t in df["tool"].unique() if t != "benign")


def get_split(exp: str, root: Path = DATA_ROOT, holdout_tool: str | None = None,
              dataset: str = "testbed"):
    """Return (train_df, test_df, result_name) for an experiment.

    exp:
      E1 within-testbed            E2 CIC benchmark
      E3 leave-one-tool-out        (needs holdout_tool; result name E3_<tool>)
      E4_cic2testbed / E4_testbed2cic
      E5 low-and-slow              (train on non-throttled, test on throttled)
      S shuffled-row split         (result name S; compare with E1 for testbed or
                                    E2 for CIC, which use the proper time split
                                    on the same data. "S_shuffled" also accepted.)
    """
    if exp == "E1":
        tr, te = time_session_split(load_queries("testbed", root))
        return tr, te, "E1"
    if exp == "E2":
        tr, te = time_session_split(load_queries("cic", root))
        return tr, te, "E2"
    if exp == "E3":
        if not holdout_tool:
            raise ValueError("E3 needs --holdout <tool>")
        tr, te = time_session_split(load_queries(dataset, root))
        tr = tr[tr["tool"] != holdout_tool]                       # unseen in training
        te = te[(te["tool"] == holdout_tool) | (te["label"] == 0)]  # that tool + benign
        return tr, te, f"E3_{holdout_tool}"
    if exp in ("E4_cic2testbed", "E4_testbed2cic"):
        src, dst = ("cic", "testbed") if exp == "E4_cic2testbed" else ("testbed", "cic")
        tr, _ = time_session_split(load_queries(src, root))
        _, te = time_session_split(load_queries(dst, root))
        return tr, te, exp
    if exp == "E5":
        tr, te = time_session_split(load_queries("testbed", root))
        slow = te["throttle"].fillna(0).astype(float) > 0
        tr = tr[(tr["label"] == 0) | (tr["throttle"].fillna(0).astype(float) == 0)]
        te = te[(te["label"] == 0) | slow]
        return tr, te, "E5"
    if exp in ("S", "S_shuffled"):
        tr, te = shuffled_split(load_queries(dataset, root))
        return tr, te, "S"
    raise ValueError(f"Unknown experiment {exp!r}")
