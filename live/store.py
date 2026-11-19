"""live/alerts.db: what the sniffer writes and the dashboard reads (SQLite).

Tables `alerts` (one row per query at or above the threshold), `host_stats` (per host per BUCKET_S seconds),
`batches` (one row per scored batch, for the latency numbers) and `meta`. Every column is documented in
live/README.md, which is what the dashboard is built against.
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
CREATE TABLE IF NOT EXISTS batches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scored_ts REAL NOT NULL,
    first_ts REAL NOT NULL,
    last_ts REAL NOT NULL,
    queries INTEGER NOT NULL,
    alerts INTEGER NOT NULL,
    process_ms REAL NOT NULL
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

    def write(
        self,
        alerts: list[dict],
        stats: dict[tuple[float, str], tuple[int, int, float, float]],
        batch: tuple[float, float, int, float] | None = None,
    ) -> None:
        """One scored batch: its alerts, and per (bucket, host) the queries, alerts, max score and score sum.

        `batch` is (first query ts, last query ts, queries, process_ms) and adds one row to `batches`,
        which is what the latency numbers are read from (live/report.py)."""
        now = time.time()
        if batch is not None:
            first_ts, last_ts, queries, process_ms = batch
            self.db.execute(
                "INSERT INTO batches (scored_ts, first_ts, last_ts, queries, alerts, process_ms) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (now, first_ts, last_ts, queries, len(alerts), process_ms),
            )
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
