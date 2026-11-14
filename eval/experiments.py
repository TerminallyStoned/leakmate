"""Train/test splits for each experiment ID (E1-E5, S) from the contract (docs/contracts.md).

The main split is the query table's `split` column ("train"/"test", decided by time
within each capture by the parser / CIC extractor), the same rule models/m1_run.py
uses. Tables without that column fall back to a time- and session-based 70/30 split.
Only experiment S shuffles rows, to show how much shuffling inflates scores.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

DATA_ROOT = Path("data/processed")
SYNTHETIC = Path("data/sample/synthetic_queries.parquet")  # scripts/make_synthetic_sample.py
TRAIN_FRAC = 0.7

# What people read. Code, file names and the contract keep the short IDs.
NAMES = {
    "E1": "Experiment 1 (within-testbed)",
    "E2": "Experiment 2 (CIC benchmark)",
    "E3": "Experiment 3 (leave-one-tool-out)",
    "E4": "Experiment 4 (cross-dataset)",
    "E5": "Experiment 5 (low-and-slow)",
    "S": "Experiment S (shuffled vs time split)",
}
EXP_HELP = "experiment ID: " + "; ".join(f"{k} = {v}" for k, v in NAMES.items())


def experiment_name(run_name: str) -> str:
    """'E3_iodine' -> 'Experiment 3 (leave-one-tool-out) - iodine'; unknown names pass through."""
    exp, _, tag = run_name.partition("_")
    if exp not in NAMES:
        return run_name
    return f"{NAMES[exp]} - {tag.replace('_', ' ')}" if tag else NAMES[exp]


def load_queries(dataset: str, root: Path = DATA_ROOT) -> pd.DataFrame:
    path = SYNTHETIC if dataset == "synthetic" else root / dataset / "queries.parquet"
    df = pd.read_parquet(path)
    return df.sort_values("ts").reset_index(drop=True)


def time_session_split(df: pd.DataFrame, train_frac: float = TRAIN_FRAC):
    """Earliest sessions go to train, later sessions to test, done per label so
    both sides contain benign and tunnel traffic. A session never straddles the cut."""
    train_parts, test_parts = [], []
    for _, part in df.groupby("label"):
        starts = part.groupby("session_id")["ts"].min().sort_values()
        cut = max(1, int(len(starts) * train_frac))
        in_train = part["session_id"].isin(set(starts.index[:cut]))
        train_parts.append(part[in_train])
        test_parts.append(part[~in_train])
    return (pd.concat(train_parts).sort_values("ts"), pd.concat(test_parts).sort_values("ts"))


def default_split(df: pd.DataFrame):
    """Return (train, test, split description) using the table's own split if it has one."""
    if "split" in df.columns:
        return df[df["split"] == "train"], df[df["split"] == "test"], "split_column"
    tr, te = time_session_split(df)
    return tr, te, f"time_session_{int(TRAIN_FRAC * 100)}_{100 - int(TRAIN_FRAC * 100)}"


def shuffled_split(df: pd.DataFrame, train_frac: float = TRAIN_FRAC, seed: int = 0):
    """The WRONG way (rows shuffled). Only used by experiment S to show the inflation."""
    shuf = df.sample(frac=1.0, random_state=seed)
    cut = int(len(shuf) * train_frac)
    desc = f"shuffled_{int(train_frac * 100)}_{100 - int(train_frac * 100)}"
    return shuf.iloc[:cut], shuf.iloc[cut:], desc


def tools_in(dataset: str, root: Path = DATA_ROOT) -> list[str]:
    df = load_queries(dataset, root)
    return sorted(t for t in df["tool"].unique() if t != "benign")


def get_split(exp: str, root: Path = DATA_ROOT, holdout_tool: str | None = None, dataset: str = "testbed"):
    """Return (train_df, test_df, experiment_id, run_name, split_desc).

    experiment_id is the contract's ID (E1..E5 or S); run_name is the results file
    name, which adds a tag where one experiment has several runs.

      E1  within-testbed                    E2  CIC benchmark
      E3  leave-one-tool-out (holdout_tool; file E3_<tool>)
      E4_cic2testbed / E4_testbed2cic       (experiment E4)
      E5  low-and-slow: train on throttle == 0 tunnels, test on throttle > 0
      S   shuffled-row split (compare with E1, or E2 when dataset="cic")

    dataset="synthetic" runs any experiment on the 1,000-row contract sample (tests only).
    E3 and S use `dataset` (default testbed; pass "cic" before testbed data exists).
    """

    def ds(default: str) -> str:
        return "synthetic" if dataset == "synthetic" else default

    if exp == "E1":
        tr, te, desc = default_split(load_queries(ds("testbed"), root))
        return tr, te, "E1", "E1", desc
    if exp == "E2":
        tr, te, desc = default_split(load_queries(ds("cic"), root))
        return tr, te, "E2", "E2", desc
    if exp == "E3":
        if not holdout_tool:
            raise ValueError("E3 needs --holdout <tool>")
        tr, te, desc = default_split(load_queries(dataset, root))
        tr = tr[tr["tool"] != holdout_tool]  # unseen in training
        te = te[(te["tool"] == holdout_tool) | (te["label"] == 0)]  # that tool + benign
        return tr, te, "E3", f"E3_{holdout_tool}", f"{desc};holdout={holdout_tool}"
    if exp in ("E4_cic2testbed", "E4_testbed2cic"):
        src, dst = ("cic", "testbed") if exp == "E4_cic2testbed" else ("testbed", "cic")
        tr, _, _ = default_split(load_queries(ds(src), root))
        _, te, _ = default_split(load_queries(ds(dst), root))
        return tr, te, "E4", exp, f"train={src};test={dst}"
    if exp == "E5":
        tr, te, desc = default_split(load_queries(ds("testbed"), root))
        tr = tr[(tr["label"] == 0) | (tr["throttle"] == 0)]
        te = te[(te["label"] == 0) | (te["throttle"] > 0)]
        return tr, te, "E5", "E5", f"{desc};train throttle==0;test throttle>0"
    if exp in ("S", "S_shuffled"):
        tr, te, desc = shuffled_split(load_queries(dataset, root))
        return tr, te, "S", "S", desc
    raise ValueError(f"Unknown experiment {exp!r}")
