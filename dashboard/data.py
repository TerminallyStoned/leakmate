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
from collections.abc import Sequence
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]

#: results/ on main, or results_nozone/ for the run with the lab domain hidden
RESULTS_ENV = "LEAKMATE_RESULTS"
ALERTS_ENV = "LEAKMATE_ALERTS_DB"
DEFAULT_DB = ROOT / "live" / "alerts.db"
LIMIT_MS = 10.0  # the selection rule's latency limit, eval.metrics.MAX_LATENCY_MS (README, Models)
MAX_FPR = 0.01  # the selection rule's false-positive ceiling, eval.metrics.MAX_FPR


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


def read_selection() -> pd.DataFrame:
    """The rule's pick per experiment, the one to quote.

    On the original testbed names every tunnel ends in tunnel.test, so a model that reads names wins
    Experiments 1, 3 and 5 from the suffix. With the default results/, those experiments are taken from
    results_nozone/ (lab domain hidden); Experiments 2 and 4 use CIC and exist only in results/.
    """
    picks = read_table("selection")
    masked = ROOT / "results_nozone" / "selection.csv"
    if picks.empty or results_dir() != ROOT / "results" or not masked.exists():
        return picks
    hidden = pd.read_csv(masked)
    kept = picks[~picks["experiment"].isin(hidden["experiment"])]
    return pd.concat([kept, hidden]).sort_values("experiment", kind="stable").reset_index(drop=True)


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


#: what a missing host is called in the UI: the row is real data, so it stays in every panel
NO_HOST = "(no host)"

#: the SQL side of `NO_HOST`. `src_host` is NOT NULL, but NOT NULL permits '', so both are covered.
_HOST_EXPR = "COALESCE(NULLIF(src_host, ''), ?)"


def _hosts(frame: pd.DataFrame) -> pd.DataFrame:
    """A NULL `src_host` becomes a name, not a dropped row.

    Without this, one unattributed query puts NaN into a set of strings and `sorted()` raises
    `'<' not supported between instances of 'float' and 'str'`, which blanks the page.
    """
    if "src_host" in frame:
        frame["src_host"] = frame["src_host"].fillna(NO_HOST).replace("", NO_HOST)
    return frame


def read_alerts(conn: sqlite3.Connection, limit: int = 5000) -> pd.DataFrame:
    """Alerts oldest first, with `top_features` decoded from its JSON string.

    The cap keeps the **newest** rows: `alerts` is appended to forever, so `ORDER BY id ASC LIMIT n` would
    hand back the oldest ones and every window control would then see an empty recent past. Panels that need a
    total - the strip, the feed - ask `alert_counts` or `alert_page` instead of counting this slice.
    """
    if not has_table(conn, "alerts"):
        return pd.DataFrame()
    sql = "SELECT * FROM alerts ORDER BY id DESC" + (f" LIMIT {int(limit)}" if limit else "")
    df = pd.DataFrame([dict(r) for r in conn.execute(sql).fetchall()])
    if df.empty:
        return df
    df = df.iloc[::-1].reset_index(drop=True)
    df["features"] = df["top_features"].fillna("[]").map(_loads)
    df = _hosts(df)
    df["host"] = df["src_host"]
    return df


#: the feed's sort menu: label -> (column, descending). A whitelist, because the widget value picks the
#: `ORDER BY` and must not be able to name anything else.
ALERT_SORTS: dict[str, tuple[str, bool]] = {
    "Newest first": ("id", True),
    "Oldest first": ("id", False),
    "Highest score": ("score", True),
    "Lowest score": ("score", False),
    "Host": ("src_host", False),
    "Query name": ("qname", False),
}


def _like(text: str) -> str:
    """A query name typed by a user, made into a LIKE pattern. `%` and `_` are text, not wildcards."""
    escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _alert_where(hosts: Sequence[str], since: float, min_score: float, search: str) -> tuple[str, list]:
    clauses: list[str] = []
    args: list = []
    if hosts:
        # the same expression `_hosts` applies to the frame: filtering on the raw column would drop every row
        # whose host was empty, because the UI only ever offers the replacement name
        clauses.append(f"{_HOST_EXPR} IN ({','.join('?' * len(hosts))})")
        args.extend([NO_HOST] + list(hosts))
    if since:
        clauses.append("ts >= ?")
        args.append(float(since))
    if min_score > 0:
        clauses.append("score >= ?")
        args.append(float(min_score))
    if search:
        clauses.append(r"qname LIKE ? ESCAPE '\'")
        args.append(_like(search))
    return (f"WHERE {' AND '.join(clauses)}" if clauses else ""), args


def alert_counts(
    conn: sqlite3.Connection, *, hosts: Sequence[str] = (), since: float = 0.0, min_score: float = 0.0, search: str = ""
) -> dict:
    """How many alerts, and how many distinct hosts, match. Counted by SQLite, not by the loaded slice."""
    if not has_table(conn, "alerts"):
        return {"alerts": 0, "hosts": 0}
    where, args = _alert_where(hosts, since, min_score, search)
    row = conn.execute(
        f"SELECT COUNT(*) AS alerts, COUNT(DISTINCT src_host) AS hosts FROM alerts {where}", args
    ).fetchone()
    return {"alerts": int(row[0]), "hosts": int(row[1])}


def count_alerts(conn: sqlite3.Connection) -> int:
    """Every alert in the file, not just the newest slice the panels load."""
    if not has_table(conn, "alerts"):
        return 0
    return int(conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0])


def alert_page(
    conn: sqlite3.Connection,
    *,
    hosts: Sequence[str] = (),
    since: float = 0.0,
    min_score: float = 0.0,
    search: str = "",
    sort: str = "Newest first",
    offset: int = 0,
    limit: int = 50,
) -> tuple[pd.DataFrame, int]:
    """One page of alerts, plus the size of the whole filtered set.

    Filtering, ordering and paging all happen in SQLite: a capture can hold hundreds of thousands of alerts and
    the page should not pay for the ones it does not show. `id DESC` breaks ties so two pages never disagree
    about the order of equal scores or equal timestamps.
    """
    if not has_table(conn, "alerts"):
        return pd.DataFrame(), 0
    where, args = _alert_where(hosts, since, min_score, search)
    total = int(conn.execute(f"SELECT COUNT(*) FROM alerts {where}", args).fetchone()[0])
    col, desc = ALERT_SORTS.get(sort, ALERT_SORTS["Newest first"])
    sql = f"SELECT * FROM alerts {where} ORDER BY {col} {'DESC' if desc else 'ASC'}, id DESC LIMIT ? OFFSET ?"
    frame = pd.DataFrame([dict(r) for r in conn.execute(sql, [*args, int(limit), int(offset)]).fetchall()])
    if not frame.empty:
        frame["features"] = frame["top_features"].fillna("[]").map(_loads)
        frame = _hosts(frame)
    return frame, total


def alert_by_id(conn: sqlite3.Connection, alert_id: int) -> pd.Series | None:
    """One alert by primary key, explanation decoded, whatever the loaded slices happen to hold."""
    if not has_table(conn, "alerts"):
        return None
    row = conn.execute("SELECT * FROM alerts WHERE id = ?", (int(alert_id),)).fetchone()
    if row is None:
        return None
    series = pd.Series(dict(row))
    series["features"] = _loads(series.get("top_features") or "[]")
    return series


def read_host_stats(conn: sqlite3.Connection) -> pd.DataFrame:
    frame = read_frame(conn, "host_stats", order="bucket_ts ASC")
    return _hosts(frame) if not frame.empty else frame


def read_batches(conn: sqlite3.Connection) -> pd.DataFrame:
    """One row per scored batch. Empty on a pre-19-Nov database, which has no `batches` table."""
    return read_frame(conn, "batches", order="scored_ts ASC")


def _loads(raw: str) -> list[dict]:
    """`top_features` decoded: always a list of objects, whatever the writer stored.

    The column is JSON text, so a half-written row or a different scorer can put anything in it. Consumers
    index the entries as dicts, so non-objects are dropped here rather than guarded at each use.
    """
    try:
        out = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return []
    return [item for item in out if isinstance(item, dict)] if isinstance(out, list) else []


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
        ("_ablation1_char", "ablation 1: character tokenizer"),
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
