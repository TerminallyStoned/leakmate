"""What a live run detected and how fast, read back from alerts.db.

    python -m live.report                              # live/alerts.db
    python -m live.report --db live/alerts.db --out docs/live_run.md

Prints Markdown: per host the queries seen and alerts raised (tunnel clients are known by their fixed lab
address, every other host counts as benign), the time from a query to its alert, and the processing time
per query. The file holds every run appended to it, so delete alerts.db before a run you want to report.
"""

from __future__ import annotations

import argparse
import numbers
import sqlite3
from pathlib import Path

import pandas as pd

from parser.testbed import LAB_IPS, _tools_map

# Tunnel client addresses in the lab (testbed/tools/docker-compose.yml). Anything else is benign.
LAB_TOOLS = {**LAB_IPS, "172.28.0.30": "iodine", "172.28.0.31": "dnscat2"}


def load(db: str | Path) -> dict[str, pd.DataFrame]:
    with sqlite3.connect(db) as con:
        # a file written before `batches` existed still reports its hosts and alerts
        has_batches = con.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'batches'").fetchone()
        batches_sql = "SELECT * FROM batches ORDER BY id" if has_batches else "SELECT 1 AS queries WHERE 0"
        return {
            "alerts": pd.read_sql("SELECT * FROM alerts ORDER BY id", con),
            "hosts": pd.read_sql(
                "SELECT src_host, SUM(queries) AS queries, SUM(alerts) AS alerts, MAX(max_score) AS max_score "
                "FROM host_stats GROUP BY src_host",
                con,
            ),
            "batches": pd.read_sql(batches_sql, con),
            "meta": pd.read_sql("SELECT key, value FROM meta", con),
        }


def per_host(hosts: pd.DataFrame, tools: dict[str, str]) -> pd.DataFrame:
    """One row per host: traffic (the tool at that address, else benign), queries, alerts, share flagged."""
    out = hosts.assign(traffic=hosts["src_host"].map(tools).fillna("benign"))
    out["flagged"] = out["alerts"] / out["queries"]
    out["_tunnel"] = out["traffic"] != "benign"
    out = out.sort_values(["_tunnel", "traffic", "src_host"], ascending=[False, True, True])
    return out[["src_host", "traffic", "queries", "alerts", "flagged", "max_score"]].reset_index(drop=True)


def totals(hosts: pd.DataFrame) -> pd.DataFrame:
    """Tunnel hosts and benign hosts summed: detection rate for the first, false-alert rate for the second."""
    grp = hosts.assign(kind=hosts["traffic"].where(hosts["traffic"] == "benign", "tunnel"))
    out = grp.groupby("kind")[["queries", "alerts"]].sum().reindex(["tunnel", "benign"]).dropna().astype(int)
    out["flagged"] = out["alerts"] / out["queries"]
    return out.reset_index()


def latency(alerts: pd.DataFrame, batches: pd.DataFrame) -> dict[str, float | int]:
    """Seconds from a query's packet time to its alert, and milliseconds of processing per query."""
    out: dict[str, float | int] = {"alerts": len(alerts), "batches": len(batches)}
    if len(alerts):
        wait = alerts["detected_ts"] - alerts["ts"]
        out |= {"alert_s_median": wait.median(), "alert_s_p95": wait.quantile(0.95), "alert_s_max": wait.max()}
    if len(batches):
        per_query = batches["process_ms"] / batches["queries"]
        oldest = batches["scored_ts"] - batches["first_ts"]
        out |= {
            "queries": int(batches["queries"].sum()),
            "ms_per_query": batches["process_ms"].sum() / batches["queries"].sum(),
            "batch_ms_per_query_median": per_query.median(),
            "batch_ms_per_query_p95": per_query.quantile(0.95),
            "batch_ms_max": batches["process_ms"].max(),
            "batch_queries_max": int(batches["queries"].max()),
            "verdict_s_median": oldest.median(),
            "verdict_s_p95": oldest.quantile(0.95),
            "verdict_s_max": oldest.max(),
        }
    return out


def _table(df: pd.DataFrame) -> str:
    def cell(col: str, v) -> str:
        if col == "flagged":
            return f"{v:.2%}"
        if col == "max_score":
            return f"{v:.4f}"
        return f"{v:,}" if isinstance(v, numbers.Integral) else str(v)

    lines = ["| " + " | ".join(df.columns) + " |", "|" + "---|" * len(df.columns)]
    lines += [
        "| " + " | ".join(cell(c, v) for c, v in zip(df.columns, row)) + " |" for row in df.itertuples(index=False)
    ]
    return "\n".join(lines)


def render(data: dict[str, pd.DataFrame], tools: dict[str, str]) -> str:
    meta = dict(zip(data["meta"]["key"], data["meta"]["value"]))
    hosts = per_host(data["hosts"], tools)
    lat = latency(data["alerts"], data["batches"])
    sniffed = meta.get("mode") == "sniff"  # a replayed packet's timestamp is not on the wall clock
    head = (
        f"Model `{meta.get('model')}`, alert at score >= {float(meta.get('threshold', 'nan')):.4f}. "
        f"Source: {meta.get('source')} ({meta.get('mode', 'mode not recorded')}), last run started "
        f"{meta.get('started_utc')}."
    )
    parts = ["## Live run", head, "### Per host", _table(hosts.astype({"queries": int, "alerts": int}))]
    parts += ["### Tunnel against benign", _table(totals(hosts))]
    parts.append("### Latency")
    if "ms_per_query" in lat:
        parts.append(
            f"- Processing (features, score, explanations): {lat['ms_per_query']:.2f} ms per query over "
            f"{lat['queries']:,} queries in {lat['batches']:,} batches; per batch, median "
            f"{lat['batch_ms_per_query_median']:.2f} and 95th percentile {lat['batch_ms_per_query_p95']:.2f} ms "
            f"per query. Slowest batch: {lat['batch_ms_max']:.0f} ms. Largest batch: {lat['batch_queries_max']:,} "
            "queries."
        )
    else:
        parts.append("- No `batches` rows: this file was written before processing time was recorded.")
    if not sniffed:
        parts.append("- Time to alert: not measured. It needs packets sniffed live, not a replayed capture.")
    else:
        if "alert_s_median" in lat:
            parts.append(
                f"- Time to alert (query on the wire to alert written), {lat['alerts']:,} alerts: median "
                f"{lat['alert_s_median']:.2f} s, 95th percentile {lat['alert_s_p95']:.2f} s, "
                f"max {lat['alert_s_max']:.2f} s."
            )
        if "verdict_s_median" in lat:
            parts.append(
                f"- Time to a verdict for the oldest query of each batch (alert or not): median "
                f"{lat['verdict_s_median']:.2f} s, 95th percentile {lat['verdict_s_p95']:.2f} s, "
                f"max {lat['verdict_s_max']:.2f} s."
            )
    return "\n\n".join(parts) + "\n"


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="python -m live.report", description=__doc__.split("\n")[0])
    ap.add_argument("--db", default="live/alerts.db")
    ap.add_argument(
        "--tools-map",
        type=_tools_map,
        help="ip=tool,ip=tool for the tunnel clients (default: the lab's four, testbed/tools/docker-compose.yml)",
    )
    ap.add_argument("--out", help="also write the Markdown here")
    a = ap.parse_args(argv)
    if not Path(a.db).exists():
        raise SystemExit(f"{a.db} not found: run the sniffer first (python -m live --help)")
    text = render(load(a.db), LAB_TOOLS if a.tools_map is None else a.tools_map)
    print(text)
    if a.out:
        Path(a.out).write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
