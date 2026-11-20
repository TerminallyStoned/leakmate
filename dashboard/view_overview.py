"""Overview: the one screen that answers "is it working, and what did we find".

Left half is the live detector (`live/alerts.db`), right half is the frozen evaluation (`results/`).
Everything here is a summary with a tab behind it: click through for the feed, the explanations, the
curves. Numbers are read, never recomputed.
"""

from __future__ import annotations

import html

import altair as alt
import pandas as pd
import streamlit as st

from dashboard import data, explain, shell


def render() -> None:
    shell.masthead(
        "leakmate / status",
        "Overview",
        "Evasive DNS tunnels, scored query by query. Live detection on the left, the frozen experiment "
        "numbers on the right.",
    )
    live = _live_summary()
    results = _results_summary()

    left, right = st.columns([1, 1], gap="large")
    with left:
        shell.section("Detector", "from <code>live/alerts.db</code>")
        shell.strip(live["cells"])
        where = "live traffic" if live.get("mode") == "sniff" else "a replayed capture"
        st.caption(f"Scoring {where} from `{live.get('source', 'unknown')}`.")
        _alerts_over_time(live["buckets"], live.get("bucket_s", 0.0))
        _top_hosts(live["hosts"])
        _latest(live["latest"])
    with right:
        shell.section("Evaluation", f"from <code>{data.results_dir().name}/</code>, tag <code>results-freeze</code>")
        shell.strip(results["cells"])
        _picks(results["selection"])
        _latency_overview(results["latency"])

    _go()


# --------------------------------------------------------------------------- live side


def _live_summary() -> dict:
    empty = {"cells": [("live data", "none", True)], "buckets": pd.DataFrame(), "hosts": pd.DataFrame(), "latest": None}
    conn = data.connect()
    if conn is None:
        return empty
    try:
        meta = data.read_meta(conn)
        alerts = data.read_alerts(conn)
        stats = data.read_host_stats(conn)
        batches = data.read_batches(conn)
    finally:
        conn.close()
    if alerts.empty and stats.empty:
        return empty

    queries = int(stats["queries"].sum()) if not stats.empty else 0
    median_ms = (
        float((batches["process_ms"] / batches["queries"].clip(lower=1)).median())
        if not batches.empty and (batches["queries"] > 0).any()
        else float("nan")
    )
    cells = [
        ("model", html.escape(str(meta.get("model", "unknown"))), False),
        ("queries scored", f"{queries:,}", False),
        ("alerts", f"{len(alerts):,}", bool(len(alerts))),
        (
            "median latency",
            f"{median_ms:.2f} <small>ms/query</small>" if median_ms == median_ms else "no batches",
            median_ms > data.LIMIT_MS,
        ),
    ]
    buckets = pd.DataFrame()
    hosts = pd.DataFrame()
    bucket_s = 0.0
    if not stats.empty:
        frame = stats.copy()
        bucket_s = _bucket_width(float(frame["bucket_ts"].max()) - float(frame["bucket_ts"].min()))
        frame["bucket"] = (frame["bucket_ts"] // bucket_s * bucket_s).astype("int64")
        buckets = frame.groupby("bucket", as_index=False).agg(queries=("queries", "sum"), alerts=("alerts", "sum"))
        hosts = (
            frame.groupby("src_host", as_index=False)
            .agg(queries=("queries", "sum"), alerts=("alerts", "sum"))
            .sort_values("alerts", ascending=False)
            .head(5)
        )
    latest = None
    if not alerts.empty:
        latest = alerts.sort_values("id", ascending=False).iloc[0].to_dict()
    return {
        "cells": cells,
        "buckets": buckets,
        "hosts": hosts,
        "latest": latest,
        "bucket_s": bucket_s,
        "mode": meta.get("mode"),
        "source": meta.get("source"),
    }


def _alerts_over_time(buckets: pd.DataFrame, bucket_s: float) -> None:
    p = shell.pal()
    if buckets.empty:
        st.caption("No scored buckets yet.")
        return
    frame = buckets.copy()
    frame["at"] = pd.to_datetime(frame["bucket"], unit="s", utc=True)
    bars = (
        alt.Chart(frame)
        .mark_bar(color=p["signal"])
        .encode(
            x=alt.X("at:T", title=None, axis=alt.Axis(format="%H:%M", labelFontSize=10)),
            y=alt.Y("alerts:Q", title="alerts"),
            tooltip=["at", "queries", "alerts"],
        )
    )
    quiet = (
        alt.Chart(frame)
        .mark_bar(color=p["fade"])
        .encode(x=alt.X("at:T", title=None), y=alt.Y("queries:Q", title=None), tooltip=["queries"])
    )
    st.altair_chart(alt.layer(quiet, bars).properties(**shell.chart(132)), use_container_width=True)
    per = f"{bucket_s / 60:g} min" if bucket_s < 3_600 else f"{bucket_s / 3_600:g} h"
    st.caption(f"Grey: queries scored per {per}. Red: of those, the alerts.")


def _top_hosts(hosts: pd.DataFrame) -> None:
    p = shell.pal()
    if hosts.empty:
        return
    chart = (
        alt.Chart(hosts)
        .mark_bar(color=p["signal"])
        .encode(
            y=alt.Y("src_host:N", title=None, sort="-x", axis=alt.Axis(labelFontSize=10)),
            x=alt.X("alerts:Q", title="alerts", axis=alt.Axis(labelFontSize=10, tickCount=4)),
            tooltip=["src_host", "queries", "alerts"],
        )
        .properties(height=min(132, 26 * len(hosts) + 24))
    )
    st.altair_chart(chart, use_container_width=True)


def _latest(latest: dict | None) -> None:
    if not latest:
        st.caption("Nothing has crossed the threshold in this database.")
        return
    when = pd.to_datetime(latest["ts"], unit="s", utc=True).strftime("%H:%M:%S UTC")
    qname = latest["qname"] if len(latest["qname"]) <= 62 else latest["qname"][:59] + "..."
    # a query name is whatever the client sent, so it is escaped before it goes into the page's HTML
    st.markdown(
        f'<div class="lm-why"><p><strong>{html.escape(str(latest["src_host"]))}</strong> at {when} - '
        f"score {latest['score']:.3f} over {latest['threshold']:.4f}</p>"
        f'<p class="lm-wire">{html.escape(qname)}</p>'
        f'<p class="lm-kv">strongest feature: '
        f"{html.escape(explain.headline(latest.get('features') or []))}</p></div>",
        unsafe_allow_html=True,
    )


# --------------------------------------------------------------------------- results side


def _results_summary() -> dict:
    summary = data.read_table("summary")
    if summary.empty:
        return {"cells": [("results", "run summarise", True)], "selection": pd.DataFrame(), "latency": pd.DataFrame()}
    selection = data.read_table("selection")
    latency = data.read_table("latency")
    headline = data.drop_variants(summary)
    cells = [
        ("models", f"{headline['model'].nunique()}", False),
        ("experiments", f"{headline['experiment'].nunique()}", False),
        ("runs", f"{len(headline):,}", False),
        ("best F1", f"{headline['f1'].max():.4f}", False),
    ]
    return {"cells": cells, "selection": selection, "latency": latency}


def _picks(selection: pd.DataFrame) -> None:
    if selection.empty:
        st.caption("No `results/selection.csv` - run `python -m eval.summarise`.")
        return
    frame = selection[["experiment", "selected_model", "f1", "fpr", "latency_ms_per_query"]].copy()
    frame["experiment"] = frame["experiment"].map(data.experiment_label)
    frame["selected_model"] = frame["selected_model"].map(data.model_label)
    frame = frame.rename(columns={"selected_model": "picked", "latency_ms_per_query": "ms/query"})
    frame["f1"] = frame["f1"].map("{:.4f}".format)
    frame["fpr"] = frame["fpr"].map("{:.2%}".format)
    frame["ms/query"] = frame["ms/query"].map("{:.2f}".format)
    shell.table(
        frame,
        [
            ("experiment", "experiment", "text"),
            ("picked", "picked by the rule", "text"),
            ("f1", "f1", "num"),
            ("fpr", "false-positive rate", "num"),
            ("ms/query", "ms/query", "num"),
        ],
    )
    name = data.results_dir().name
    st.caption(f"`{name}/selection.csv`: best F1 with a false-positive rate of at most 1% and at most 10 ms per query.")
    _selection_note(name)


def _selection_note(results_name: str) -> None:
    """Which selection this is. The original testbed names all end in the lab domain, which a model can read."""
    if results_name == "results_nozone":
        st.caption(
            "These are the runs with the lab domain hidden: the selection to quote for the testbed experiments "
            "(docs/suffix-ablation.md). Experiments 2 and 4 use CIC and are only in `results/`."
        )
    elif results_name == "results":
        st.caption(
            "Experiments 1, 3 and 5 here use the original testbed names, where every tunnel name ends in "
            "`tunnel.test`, so a model that reads names scores perfectly from the suffix. For those experiments "
            "quote the selection with the domain hidden: `LEAKMATE_RESULTS=results_nozone` "
            "(docs/suffix-ablation.md)."
        )


def _latency_overview(latency: pd.DataFrame) -> None:
    p = shell.pal()
    if latency.empty:
        return
    frame = data.drop_variants(latency).copy()
    frame["model"] = frame["model"].map(data.model_label)
    frame["under"] = frame["latency_ms_median"] < data.LIMIT_MS
    chart = (
        alt.Chart(frame)
        .mark_bar(size=12)
        .encode(
            x=alt.X(
                "model:N",
                title=None,
                sort=sorted(frame["model"]),
                axis=alt.Axis(labelAngle=-25, labelLimit=90, labelFontSize=10),
            ),
            y=alt.Y("latency_ms_median:Q", title="ms per query", axis=alt.Axis(tickCount=4)),
            color=alt.Color(
                "under:N", scale=alt.Scale(domain=[True, False], range=[p["signal"], p["fade"]]), legend=None
            ),
            tooltip=["model", "latency_ms_median"],
        )
    )
    rule = (
        alt.Chart(pd.DataFrame({"limit": [data.LIMIT_MS]}))
        .mark_rule(color=p["ink2"], strokeDash=[4, 3])
        .encode(y="limit:Q")
    )
    st.altair_chart(alt.layer(chart, rule).properties(**shell.chart(132)), use_container_width=True)
    st.caption(f"Red is under the {data.LIMIT_MS:.0f} ms rule (dashed). Median of three timings on one CPU box.")


# --------------------------------------------------------------------------- navigation


def _go() -> None:
    cols = st.columns(3)
    cols[0].button(
        "Live detail: feed, explanations, latency ->", on_click=_open, args=("Live",), use_container_width=True
    )
    cols[1].button(
        "Results detail: curves, per tool, split order ->", on_click=_open, args=("Results",), use_container_width=True
    )
    cols[2].markdown("&nbsp;")


def _open(page: str) -> None:
    st.session_state["page"] = page


def _bucket_width(span_s: float) -> float:
    """A bucket width that keeps the mini chart under about two dozen bars."""
    for width in (60.0, 300.0, 900.0, 1_800.0, 3_600.0, 14_400.0, 86_400.0):
        if span_s <= 24 * width:
            return width
    return 604_800.0


def _num(value) -> str:
    try:
        return f"{float(value):.4f}"
    except (TypeError, ValueError):
        return "-"
