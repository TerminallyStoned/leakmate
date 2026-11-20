"""Write a synthetic `live/alerts.db` so the dashboard can be built, checked and screenshotted before
any capture run exists (Trello card 31: "Build against fake data from 18 Nov; don't wait").

    python -m dashboard.demo                      # -> /tmp/demo_alerts.db
    LEAKMATE_ALERTS_DB=/tmp/demo_alerts.db streamlit run dashboard/app.py

Everything in the file is invented: names, scores, timings. It proves the layout, the SQL and the
plain-words explanations. It is never a source of reported numbers - those come from `results/`, which
this script does not touch. Schema follows live/README.md. Every timestamp is on the demo's own fixed clock:
`live.store` stamps `alerts.detected_ts` and `batches.scored_ts` with the wall clock, which would put them years
after the demo's packet times, so this script writes those two columns itself after the store has closed.
"""

from __future__ import annotations

import argparse
import math
import random
import sqlite3
from pathlib import Path

from live.store import AlertStore

THRESHOLD = 0.4999  # M1's validation threshold, results/m1/E1.json
MODEL = "m1_xgb"
BENIGN = ("172.28.0.10", "172.28.0.11", "172.28.0.12")
TUNNEL = ("172.28.0.43", "172.28.0.44")
BENIGN_NAMES = (
    "ntp.ubuntu.com",
    "update.code.visualstudio.com",
    "cdn.jsdelivr.net",
    "api.github.com",
    "objects.githubusercontent.com",
    "registry.npmjs.org",
    "pypi.org",
    "dl.google.com",
)
BUCKET_S = 10.0
MINUTES = 30

#: live/README.md, "batches". Created here if the store that wrote the file did not.
_BATCH_DDL = """
CREATE TABLE IF NOT EXISTS batches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scored_ts REAL NOT NULL,
    first_ts REAL NOT NULL,
    last_ts REAL NOT NULL,
    queries INTEGER NOT NULL,
    alerts INTEGER NOT NULL,
    process_ms REAL NOT NULL
);
"""


def benign_name(rng: random.Random) -> str:
    host = rng.choice(BENIGN_NAMES)
    return rng.choice([host, f"www.{host}", f"assets.{host}", f"{rng.randint(1, 99)}.e.{host}"])


def tunnel_name(rng: random.Random) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    block = "".join(rng.choice(alphabet) for _ in range(rng.choice([32, 40, 48, 56])))
    return f"{rng.randint(0, 999)}.{block}.{'exfil' if rng.random() < 0.5 else 'c2'}.tunnel.test"


def score_of(name: str, qpm: float, tunnel: bool, rng: random.Random) -> float:
    """A stand-in for the model, not a model: tunnels land near 1 and benign near 0, so every panel of the
    dashboard has something to show. Real separation comes from M1, never from this file."""
    if tunnel:
        return min(0.995, 0.56 + 0.4 * rng.random() + min(0.05, qpm / 4000))
    return 0.04 + 0.16 * rng.random()


def top_features(name: str, qpm: float) -> list[dict]:
    first = name.split(".")[0]
    return [
        {"feature": "q_len", "value": float(len(name)), "shap": round(0.9 + len(name) / 120, 2)},
        {"feature": "sub_entropy", "value": round(_entropy(first), 2), "shap": round(0.4 + _entropy(first) / 12, 2)},
        {"feature": "h_qpm", "value": round(qpm, 1), "shap": round(min(1.4, qpm / 220), 2)},
    ]


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    return -sum((text.count(c) / len(text)) * math.log2(text.count(c) / len(text)) for c in set(text))


def build(out: Path, minutes: int = MINUTES, seed: int = 32) -> dict[str, int]:
    """Write `minutes` of synthetic traffic to `out`, replacing it. Returns row counts."""
    rng = random.Random(seed)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.unlink(missing_ok=True)
    store = AlertStore(out, model=MODEL, threshold=THRESHOLD, source="br-ict3214-testbed-lab", mode="sniff")
    t0 = 1_700_000_000.0  # fixed base, so two runs are comparable
    counts = {"queries": 0, "alerts": 0, "batches": 0}
    batches: list[tuple[float, float, float, int, int, float]] = []  # one row per bucket, on the demo clock
    detected: list[float] = []  # one per alert, in the order the store inserts them
    try:
        for step in range(int(minutes * 60 // BUCKET_S)):
            bucket = t0 + step * BUCKET_S
            stats: dict[tuple[float, str], tuple[int, int, float, float]] = {}
            alerts: list[dict] = []
            for host in BENIGN + TUNNEL:
                n = rng.randint(6, 14) if host in TUNNEL else rng.randint(1, 4)
                for _ in range(n):
                    name, qtype, qpm = _traffic(host, n, rng)
                    score = score_of(name, qpm, host in TUNNEL, rng)
                    _add(stats, bucket, host, score, int(score >= THRESHOLD))
                    if score >= THRESHOLD:
                        alerts.append(_alert(bucket, host, name, qtype, score, qpm, rng))
            queries = sum(q for q, *_ in stats.values())
            process_ms = queries * rng.uniform(1.6, 5.4)
            store.write(alerts, stats)
            last = bucket + BUCKET_S
            batches.append((last + process_ms / 1000, bucket, last, queries, len(alerts), process_ms))
            detected += [a["detected_ts"] for a in alerts]
            counts["queries"] += queries
            counts["alerts"] += len(alerts)
            counts["batches"] += 1
    finally:
        store.close()
    _restamp(out, batches, detected)
    return counts


def _traffic(host: str, n: int, rng: random.Random) -> tuple[str, str, float]:
    if host in TUNNEL:
        return tunnel_name(rng), rng.choice(["TXT", "NULL", "A"]), n * 6.0
    return benign_name(rng), "A", n * 6.0


def _add(stats, bucket: float, host: str, score: float, is_alert: int) -> None:
    key = (bucket, host)
    q, a, mx, total = stats.get(key, (0, 0, 0.0, 0.0))
    stats[key] = (q + 1, a + is_alert, max(mx, score), total + score)


def _alert(bucket: float, host: str, name: str, qtype: str, score: float, qpm: float, rng) -> dict:
    return {
        "ts": bucket,
        "src_host": host,
        "qname": name,
        "qtype": qtype,
        "score": round(float(score), 6),
        "threshold": THRESHOLD,
        "model": MODEL,
        "top_features": top_features(name, qpm),
        "detected_ts": bucket + rng.uniform(0.2, 1.6),
    }


def _restamp(path: Path, batches: list[tuple[float, float, float, int, int, float]], detected: list[float]) -> None:
    """Put `batches` and `alerts.detected_ts` on the demo clock (the store stamped them with the wall clock)."""
    with sqlite3.connect(path) as db:
        db.executescript(_BATCH_DDL)
        db.execute("DELETE FROM batches")
        db.executemany(
            "INSERT INTO batches (scored_ts, first_ts, last_ts, queries, alerts, process_ms) VALUES (?, ?, ?, ?, ?, ?)",
            batches,
        )
        ids = [row[0] for row in db.execute("SELECT id FROM alerts ORDER BY id")]
        db.executemany("UPDATE alerts SET detected_ts = ? WHERE id = ?", zip(detected, ids, strict=True))
        db.commit()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m dashboard.demo", description="Write a synthetic alerts.db.")
    ap.add_argument("--out", default="/tmp/demo_alerts.db", help="database to write (default /tmp/demo_alerts.db)")
    ap.add_argument("--minutes", type=int, default=MINUTES, help="minutes of synthetic traffic (default 30)")
    ap.add_argument("--seed", type=int, default=32, help="group 32")
    a = ap.parse_args(argv)

    counts = build(Path(a.out), a.minutes, a.seed)
    print(
        f"demo data -> {a.out}: {counts['queries']:,} queries, {counts['alerts']:,} alerts, {counts['batches']} batches"
    )
    print("synthetic only: layout and screenshots, never reported numbers.")
    print(f"view it with:  LEAKMATE_ALERTS_DB={a.out} streamlit run dashboard/app.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
