"""live/alerts.db: what the sniffer writes and the dashboard reads (SQLite).

Tables
  alerts      one row per query whose score reached the threshold
  host_stats  queries, alerts and scores per host per BUCKET_S seconds (score over time, alert rate)
  meta        key/value: schema_version, model, threshold, source, started_utc

Columns of `alerts`
  id            INTEGER  row id, increasing
  ts            REAL     query time, epoch seconds UTC (the packet timestamp, as in the query table)
  src_host      TEXT     IP address of the client that sent the query
  qname         TEXT     query name as seen on the wire
  qtype         TEXT     record type mnemonic (A, TXT, NULL, ...)
  score         REAL     model score, higher = more suspicious
  threshold     REAL     threshold the score was compared with
  model         TEXT     scorer that produced it (dummy, m1_xgb, ...)
  top_features  TEXT     JSON list, most important first: [{"feature": str, "value": float, "shap": float|null}]
  detected_ts   REAL     wall-clock time the alert was written; detected_ts - ts is the time to alert
"""

from __future__ import annotations

import json
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "1"
BUCKET_S = 10.0
ALERT_COLS = ["ts", "src_host", "qname", "qtype", "score", "threshold", "model", "top_features", "detected_ts"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    src_host TEXT NOT NULL,
    qname TEXT NOT NULL,
    qtype TEXT NOT NULL,
    score REAL NOT NULL,
    threshold REAL NOT NULL,
    model TEXT NOT NULL,
    top_features TEXT NOT NULL,
    detected_ts REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS alerts_ts ON alerts (ts);
CREATE INDEX IF NOT EXISTS alerts_host_ts ON alerts (src_host, ts);
CREATE TABLE IF NOT EXISTS host_stats (
    bucket_ts REAL NOT NULL,
    src_host TEXT NOT NULL,
    queries INTEGER NOT NULL,
    alerts INTEGER NOT NULL,
    max_score REAL NOT NULL,
    sum_score REAL NOT NULL,
    PRIMARY KEY (bucket_ts, src_host)
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


class AlertStore:
    """Writer for alerts.db. One sniffer per connection; readers (the dashboard) open the file themselves."""

    def __init__(self, path: str | Path, **meta: object) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path, timeout=30)
        self.db.executescript(_SCHEMA)
        started = datetime.now(timezone.utc).isoformat(timespec="seconds")
        for key, value in {"schema_version": SCHEMA_VERSION, "started_utc": started, **meta}.items():
            self.db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, str(value)))
        self.db.commit()

    def write(self, alerts: list[dict], stats: dict[tuple[float, str], tuple[int, int, float, float]]) -> None:
        """One scored batch: its alerts, and per (bucket, host) the queries, alerts, max score and score sum."""
        now = time.time()
        self.db.executemany(
            f"INSERT INTO alerts ({', '.join(ALERT_COLS)}) VALUES ({', '.join('?' * len(ALERT_COLS))})",
            [
                (a["ts"], a["src_host"], a["qname"], a["qtype"], a["score"], a["threshold"], a["model"],
                 json.dumps(a["top_features"]), now)
                for a in alerts
            ],
        )  # fmt: skip
        self.db.executemany(
            "INSERT INTO host_stats (bucket_ts, src_host, queries, alerts, max_score, sum_score) "
            "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (bucket_ts, src_host) DO UPDATE SET "
            "queries = queries + excluded.queries, alerts = alerts + excluded.alerts, "
            "max_score = max(max_score, excluded.max_score), sum_score = sum_score + excluded.sum_score",
            [(bucket, host, *vals) for (bucket, host), vals in stats.items()],
        )
        self.db.commit()

    def close(self) -> None:
        self.db.close()
