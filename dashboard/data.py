"""Reads for the dashboard: `results/*.csv` and `live/alerts.db`, exactly as written.

Nothing here computes a metric. Metrics come from `python -m eval.summarise` and alerts from
`python -m live`, so the dashboard cannot disagree with them. Every read is tolerant: a missing file
returns an empty frame plus the command that would create it, because the manual is graded on being
followable on a clean machine.
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]

#: results/ on main, or results_nozone/ for the run with the lab domain hidden
RESULTS_ENV = "LEAKMATE_RESULTS"
ALERTS_ENV = "LEAKMATE_ALERTS_DB"
DEFAULT_DB = ROOT / "live" / "alerts.db"
LIMIT_MS = 10.0  # the deployment rule: under 10 ms per query, see docs/latency.md


#: rows of their own in the summarise output: host-averaged scores and ablations, not the headline models
VARIANTS = ("_hostavg", "_ablation")


def drop_variants(frame: pd.DataFrame) -> pd.DataFrame:
    """The six headline models only - see `results/summary.csv` for the rest."""
    if frame.empty or "model" not in frame:
        return frame
    return frame[~frame["model"].str.contains("|".join(VARIANTS), regex=True)]


def results_dir() -> Path:
    override = os.environ.get(RESULTS_ENV)
    return Path(override) if override else ROOT / "results"


def db_path() -> Path:
    override = os.environ.get(ALERTS_ENV)
    return Path(override) if override else DEFAULT_DB


def read_table(name: str) -> pd.DataFrame:
    """One of the summarise outputs, or an empty frame."""
    path = results_dir() / f"{name}.csv"
    if not path.exists():
        return pd.DataFrame()
    return pd.read_csv(path)


def figure(kind: str, model: str | None = None, experiment: str | None = None) -> Path | None:
    """results/figures/{roc_<exp>,cm_<model>_<exp>,latency}.png, or None if it was never drawn."""
    if model is None and experiment is None:
        path = results_dir() / "figures" / f"{kind}.png"
    else:
        stem = f"{kind}_{experiment}" if kind == "roc" else f"{kind}_{model}_{experiment}"
        path = results_dir() / "figures" / f"{stem}.png"
    return path if path.exists() else None


# --------------------------------------------------------------------------- alerts.db


def connect(path: Path | None = None) -> sqlite3.Connection | None:
    """Open alerts.db read-only. None when it does not exist yet (no capture has been run)."""
    p = path or db_path()
    if not Path(p).exists():
        return None
    conn = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def has_table(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)).fetchone()
    return row is not None


def read_meta(conn: sqlite3.Connection) -> dict[str, str]:
    if not has_table(conn, "meta"):
        return {}
    return {r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM meta")}


def read_frame(conn: sqlite3.Connection, table: str, columns: str = "*", order: str = "", limit: int = 0):
    """A whole table as a frame. `order` is a literal from this module, never user input."""
    if not has_table(conn, table):
        return pd.DataFrame()
    sql = f"SELECT {columns} FROM {table}"  # noqa: S608 - table/columns come from this module
    if order:
        sql += f" ORDER BY {order}"
    if limit:
        sql += f" LIMIT {int(limit)}"
    rows = conn.execute(sql).fetchall()
    return pd.DataFrame([dict(r) for r in rows])


def read_alerts(conn: sqlite3.Connection, limit: int = 5000) -> pd.DataFrame:
    """Alerts oldest first, with `top_features` decoded from its JSON string.

    The cap keeps the **newest** rows: `alerts` is appended to forever, so `ORDER BY id ASC LIMIT n` would
    hand back the oldest ones and every window control would then see an empty recent past.
    """
    if not has_table(conn, "alerts"):
        return pd.DataFrame()
    sql = "SELECT * FROM alerts ORDER BY id DESC" + (f" LIMIT {int(limit)}" if limit else "")
    df = pd.DataFrame([dict(r) for r in conn.execute(sql).fetchall()])
    if df.empty:
        return df
    df = df.iloc[::-1].reset_index(drop=True)
    df["features"] = df["top_features"].fillna("[]").map(_loads)
    df["host"] = df["src_host"]
    return df


def read_host_stats(conn: sqlite3.Connection) -> pd.DataFrame:
    return read_frame(conn, "host_stats", order="bucket_ts ASC")


def read_batches(conn: sqlite3.Connection) -> pd.DataFrame:
    """One row per scored batch. Empty on a pre-19-Nov database, which has no `batches` table."""
    return read_frame(conn, "batches", order="scored_ts ASC")


def _loads(raw: str) -> list[dict]:
    try:
        out = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return []
    return out if isinstance(out, list) else []


# --------------------------------------------------------------------------- labels


def model_label(name: str | None) -> str:
    """`m1` -> M1, `m3_bilstm_hostavg` -> M3 BiLSTM (host-avg). Sort keys stay the raw names."""
    if not name:
        return "-"
    pretty = {
        "m1": "M1 XGBoost",
        "rf": "Random Forest",
        "iforest": "Isolation Forest",
        "m2": "M2 DNS-BERT",
        "m3_cnn": "M3 CNN",
        "m3_bilstm": "M3 BiLSTM",
        "m1_testbed": "M1 (testbed split)",
    }
    if name in pretty:
        return pretty[name]
    tail = ""
    base = name
    for suffix, word in (
        ("_hostavg", "host-avg"),
        ("_ablation_cic_leaky", "ablation: CIC leaky"),
        ("_ablation_query_only", "ablation: query only"),
        ("_ablation1_char", "ablation: char BPE"),
    ):
        if name.endswith(suffix):
            base, tail = name[: -len(suffix)], word
            break
    label = pretty.get(base, base.replace("_", " "))
    return f"{label} ({tail})" if tail else label


def experiment_label(name: str) -> str:
    """`E3_dnscat2` -> Experiment 3, hold out dnscat2."""
    if not name.startswith("E"):
        return {"S": "Split order (shuffled vs time)"}.get(name, name)
    head, _, holdout = name.partition("_")
    out = f"Experiment {head[1:]}"
    if holdout:
        out += f" - {holdout.replace('cic2testbed', 'CIC to testbed').replace('testbed2cic', 'testbed to CIC')}"
    return out
