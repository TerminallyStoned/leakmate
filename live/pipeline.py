"""Frames -> queries -> features -> scores -> alerts.

    frame source (live/capture.py)
      -> QueryAssembler   parser.pcap.dns_packet per frame; pairs each query with its reply
      -> HostWindows      the M1 feature set (models.m1_features), host part on each host's last `window_s` s
      -> scorer           live/scorers.py (a model behind the contract interface, M1 by default; or dummy)
      -> AlertStore       live/store.py (alerts.db)

Nothing here re-implements parsing or features: the frame decoder is the file parser's, and the features
are the ones M1 is trained on, so a live row gets the values the same query would get offline.

Two things differ from parsing a finished capture, both because a live query cannot wait forever:
  - a query is scored once its reply has been seen, or after `reply_wait` seconds without one
    (resp_size 0, rcode -1, as in the query table). A reply that arrives later is ignored;
  - queries are released in arrival order, so one unanswered query delays the ones behind it by at most
    `reply_wait`. This keeps every host window identical to the offline one.
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Iterable

import pandas as pd

from live.store import BUCKET_S, AlertStore
from models import host_features, m1_features
from parser.pcap import MALFORMED, dns_packet

QUERY_COLS = ["ts", "src_host", "qname", "qtype", "resp_size", "rcode", "qname_truncated", "qlen_wire"]


class QueryAssembler:
    """Turns captured frames into query rows, each with its reply's size and rcode when one arrived in time."""

    def __init__(self, ignore_src: Iterable[str] = (), reply_wait: float = 1.0) -> None:
        self.ignore = set(ignore_src)  # senders to drop, e.g. the resolver (its forwarded copies of a lookup)
        self.reply_wait = reply_wait
        self._queue: deque[dict] = deque()  # every query not yet released, oldest first
        self._open: dict[tuple, dict] = {}  # queries still waiting for a reply, by (client, port, DNS id)

    def feed(self, ts: float, buf: bytes) -> None:
        try:
            pkt = dns_packet(buf)
        except MALFORMED:
            return
        if pkt is None:
            return
        kind, key, val = pkt
        if kind == "query":
            if val["src_host"] in self.ignore or key in self._open:  # second case: a retransmission
                return
            row = {"ts": float(ts), **val, "_key": key, "_done": False}
            self._open[key] = row
            self._queue.append(row)
        else:
            row = self._open.pop(key, None)
            if row is not None:
                row["resp_size"], row["rcode"] = val
                row["_done"] = True

    def release(self, now: float | None = None) -> list[dict]:
        """Queries ready to score, oldest first. `now=None` releases everything (end of the capture)."""
        out = []
        while self._queue:
            row = self._queue[0]
            if not row["_done"] and now is not None and now - row["ts"] < self.reply_wait:
                break
            self._queue.popleft()
            if not row["_done"]:
                self._open.pop(row["_key"], None)
            out.append({c: row[c] for c in QUERY_COLS})
        return out


class HostWindows:
    """The M1 feature set for live queries, from each host's own recent queries (past only)."""

    def __init__(self, window_s: float = m1_features.DEFAULT_CFG["window_s"]) -> None:
        self.window_s = window_s
        self._recent: dict[str, deque[dict]] = {}  # per host: its queries of the last window_s seconds

    def features(self, rows: list[dict]) -> pd.DataFrame:
        """One feature row per query in `rows` (time-ordered), in the same order."""
        hosts = dict.fromkeys(r["src_host"] for r in rows)
        history = [r for h in hosts for r in self._recent.get(h, ())]
        table = pd.DataFrame(history + rows, columns=QUERY_COLS)
        new = table.iloc[len(history) :]
        # The two halves of m1_features.build, each on the rows it needs: the per-query features read one row
        # at a time, so only the new rows; the host features read the window, so the history as well. Building
        # everything on the whole table gave the same values at about ten times the cost on a busy host.
        per_query = m1_features.build(new, {"host": False})
        per_host = host_features.compute(table, self.window_s, key=m1_features.host_key(table)).iloc[len(history) :]
        feats = per_query.join(per_host).reset_index(drop=True)
        for r in rows:
            self._recent.setdefault(r["src_host"], deque()).append(r)
        for h in hosts:  # keep only what a later query of this host can still see
            win = self._recent[h]
            while win and win[0]["ts"] <= win[-1]["ts"] - self.window_s:
                win.popleft()
        return feats

    def prune(self, now: float) -> None:
        """Forget hosts that have been silent for a whole window."""
        for h in [h for h, win in self._recent.items() if win[-1]["ts"] <= now - self.window_s]:
            del self._recent[h]


class Detector:
    """Scores released queries and writes the alerts."""

    def __init__(self, scorer, store: AlertStore, window_s: float = m1_features.DEFAULT_CFG["window_s"]) -> None:
        self.scorer, self.store = scorer, store
        self.windows = HostWindows(window_s)
        self.queries = self.alerts = 0
        self.last_alert: dict | None = None

    def process(self, rows: list[dict]) -> int:
        """Score one batch; returns the number of alerts written."""
        if not rows:
            return 0
        t0 = time.perf_counter()
        df = pd.DataFrame(rows, columns=QUERY_COLS).join(self.windows.features(rows).add_prefix(m1_features.PREFIX))
        scores = self.scorer.score(df)
        hit = scores >= self.scorer.threshold
        flagged = df[hit]
        tops = self.scorer.explain(flagged) if len(flagged) else []
        process_ms = (time.perf_counter() - t0) * 1000  # features + score + explanations for this batch
        alerts = [
            {
                "ts": r.ts,
                "src_host": r.src_host,
                "qname": r.qname,
                "qtype": r.qtype,
                "score": float(s),
                "threshold": float(self.scorer.threshold),
                "model": self.scorer.name,
                "top_features": top,
            }
            for r, s, top in zip(flagged.itertuples(), scores[hit], tops)
        ]
        stats: dict[tuple[float, str], tuple[int, int, float, float]] = {}
        for r, s, h in zip(df.itertuples(), scores, hit):
            key = (r.ts // BUCKET_S * BUCKET_S, r.src_host)
            n, a, mx, sm = stats.get(key, (0, 0, 0.0, 0.0))
            stats[key] = (n + 1, a + int(h), max(mx, float(s)), sm + float(s))
        self.store.write(alerts, stats, (rows[0]["ts"], rows[-1]["ts"], len(rows), process_ms))
        self.queries += len(rows)
        self.alerts += len(alerts)
        if alerts:
            self.last_alert = alerts[-1]
        return len(alerts)


def run(source, assembler: QueryAssembler, detector: Detector, batch_s: float = 0.5, status_s: float = 10.0) -> None:
    """Drive the pipeline from a frame source until it ends (a pcap) or the user stops it (an interface).

    `source` yields (timestamp, frame); a frame of None is a clock tick with no packet, which a live source
    sends while the wire is quiet so waiting queries are still released on time."""
    last_batch = last_status = None
    try:
        for ts, buf in source:
            if buf is not None:
                assembler.feed(ts, buf)
            if last_batch is None:
                last_batch = last_status = ts
            if ts - last_batch >= batch_s:
                detector.process(assembler.release(ts))
                detector.windows.prune(ts)
                last_batch = ts
            if ts - last_status >= status_s:
                print(status(detector), flush=True)
                last_status = ts
    except KeyboardInterrupt:
        pass
    detector.process(assembler.release())
    print(status(detector), flush=True)


def status(detector: Detector) -> str:
    line = f"{time.strftime('%H:%M:%S')} queries {detector.queries}  alerts {detector.alerts}"
    a = detector.last_alert
    return line if a is None else f"{line}  last: {a['src_host']} {a['qname'][:60]} score {a['score']:.3f}"
