"""Live page: what the detector is seeing right now, and why it alerted.

Built against `live/alerts.db` as documented in live/README.md: `alerts`, `host_stats`, `batches`
(19 Nov) and `meta`. Every panel degrades to a message naming the command that fills it.
"""

from __future__ import annotations

import html
import sqlite3

import altair as alt
import pandas as pd
import streamlit as st

from dashboard import data, explain, shell

#: the section a clicked alert opens in
TRIGGER_TAB = "Alert trigger"


def render() -> None:
    conn = data.connect()
    shell.masthead(
        "leakmate / detection in progress",
        "Live",
        "Every DNS query the sniffer scores, the ones that crossed the threshold, and the features that put "
        "them over it.",
    )
    if conn is None:
        _empty_db()
        return
    try:
        _open_clicked_alert()  # before the tab strip is built
        meta = data.read_meta(conn)
        alerts = data.read_alerts(conn)
        stats = data.read_host_stats(conn)
        batches = data.read_batches(conn)
        if alerts.empty and stats.empty:
            shell.need(
                "The database holds no rows yet.",
                "Start the sniffer: `python -m live --pcap <capture>.pcap` (M1 by default).",
            )
            return
        view = _controls(alerts, stats, batches)
        alerts, stats, batches = _clip(view["since"], view["hosts"], alerts, stats, batches)
        counts = data.alert_counts(conn, hosts=view["hosts"], since=view["since"])
        _strip(meta, stats, batches, view["note"], counts)
        # bound to the URL so a feed row can land on the trigger panel directly; a callback-assigned
        # session_state value does not move a tab, this does
        feed, trend, why, latency = st.tabs(
            ["Alert feed", "Score over time", "Alert trigger", "Latency"], key="live_section", bind="query-params"
        )
        with trend:
            _score_over_time(stats, alerts)
        with feed:
            _feed(conn, view)
        with why:
            _why(conn)
        with latency:
            _latency(batches, meta)
    finally:
        conn.close()


# --------------------------------------------------------------------------- pieces


def _empty_db() -> None:
    shell.need(
        "No `live/alerts.db` yet.",
        "Run the sniffer over a capture (no root, no Docker needed), then reload this page:\n\n"
        "```\npython -m live --pcap data/raw/tools/<capture>.pcap\n```\n\n"
        "In the testbed instead: `live/run_live.sh --at bridge`. Both run M1 from `artifacts/m1_xgb/E1.pt`. "
        "To look at the layout before any capture exists, write a demo database with "
        "`python -m dashboard.demo` and point the app at it with "
        "`LEAKMATE_ALERTS_DB=/tmp/demo_alerts.db streamlit run dashboard/app.py`.",
    )


def _controls(alerts: pd.DataFrame, stats: pd.DataFrame, batches: pd.DataFrame) -> dict:
    """Window and host filter, applied to every panel on the page.

    The sniffer appends each run to `live/alerts.db` and never trims it, so a window is how you look at one
    run: `meta.started_utc` says when the last one began, and the file may hold several.
    """
    first, last = _span(alerts, stats, batches)
    minutes = max(1, int((last - first) // 60) + 1) if last > first else 1
    hosts = sorted(set(stats.get("src_host", pd.Series(dtype=str))) | set(alerts.get("src_host", pd.Series(dtype=str))))
    cols = st.columns([2, 1])
    window = cols[0].slider(
        "Last",
        min_value=1,
        max_value=max(minutes, 5),
        value=min(minutes, 60),
        step=1,
        format="%d min",
        key="lm_window",
        help="Most recent window of the recorded traffic. Applies to the strip, the feed, the charts and "
        "the latency tab. `live/alerts.db` holds every run the sniffer appended, newest at the end.",
    )
    only_alerts = cols[1].checkbox("Alerting hosts only", value=False, key="lm_alerting_only")
    if only_alerts and not alerts.empty:
        keep = set(alerts["src_host"].unique())
        hosts = [h for h in hosts if h in keep]
    note = (
        f"Last {window} min of a {minutes} min file"
        if window < minutes
        else f"Whole file: {minutes} min, {first and _clock(first)} to {_clock(last)} UTC"
    )
    if only_alerts:
        note += ", alerting hosts only"
    return {"hosts": hosts, "since": last - window * 60, "note": note}


def _span(alerts: pd.DataFrame, stats: pd.DataFrame, batches: pd.DataFrame) -> tuple[float, float]:
    """Earliest and latest timestamp on the page, across the three tables."""
    stamps = [
        float(frame[column].min() if which == "min" else frame[column].max())
        for frame, column in ((alerts, "ts"), (stats, "bucket_ts"), (batches, "scored_ts"))
        if not frame.empty and column in frame
        for which in ("min", "max")
    ]
    return (min(stamps), max(stamps)) if stamps else (0.0, 0.0)


def _clock(stamp: float) -> str:
    return pd.to_datetime(stamp, unit="s", utc=True).strftime("%H:%M")


def _clip(since: float, hosts: list[str], *frames: pd.DataFrame) -> tuple[pd.DataFrame, ...]:
    """Window and host filter for a frame, using whichever time and host columns it has."""
    out = []
    for frame in frames:
        if frame.empty:
            out.append(frame)
            continue
        for column in ("ts", "bucket_ts", "scored_ts"):
            if column in frame:
                frame = frame[frame[column] >= since]
                break
        if hosts and "src_host" in frame:
            frame = frame[frame["src_host"].isin(hosts)]
        out.append(frame)
    return tuple(out)


def _strip(
    meta: dict,
    stats: pd.DataFrame,
    batches: pd.DataFrame,
    note: str,
    counts: dict,
) -> None:
    """The counters above the tabs. Alerts and alerting hosts are counted in SQL over the same window the
    page filtered to, because the loaded frame is capped and a count off it would be a lie on a big capture.
    """
    queries = int(stats["queries"].sum()) if not stats.empty and "queries" in stats else 0
    alerting = counts["hosts"]
    hosts = max(stats["src_host"].nunique() if not stats.empty else 0, 0)
    rate = (counts["alerts"] / queries * 100) if queries else 0.0
    cells = [
        ("model", html.escape(str(meta.get("model", "unknown"))), False),
        ("threshold", _num(meta.get("threshold")), False),
        ("queries scored", f"{queries:,}", False),
        ("alerts", f"{counts['alerts']:,}", bool(counts["alerts"])),
        ("hosts alerting", f"{alerting} of {hosts}", alerting > 0),
        ("alert rate", f"{rate:.2f}%", False),
    ]
    if not batches.empty:
        ms = _median_per_query(batches)
        cells.append(("median latency", f"{ms:.2f} <small>ms/query</small>", ms > data.LIMIT_MS))
    cells.append(("mode", html.escape(str(meta.get("mode", "unknown"))), False))
    shell.strip(cells)
    st.caption(note + ".")


def _num(value) -> str:
    try:
        return f"{float(value):.4f}"
    except (TypeError, ValueError):
        return "-"


def _score_over_time(stats: pd.DataFrame, alerts: pd.DataFrame) -> None:
    p = shell.pal()
    st.markdown('<div class="lm-sec">Score over time</div>', unsafe_allow_html=True)
    if stats.empty:
        st.caption("`host_stats` is empty, so there is nothing to plot.")
        return
    frame = stats.copy()
    if frame.empty:
        st.caption("No traffic in this window.")
        return
    frame["mean_score"] = frame["sum_score"] / frame["queries"].clip(lower=1)
    top = frame["src_host"].value_counts().head(6).index.tolist()
    frame = frame[frame["src_host"].isin(top)].copy()
    # bucket_ts is epoch seconds; the axis and tooltips show it in UTC, like every other time on the page
    frame["at"] = pd.to_datetime(frame["bucket_ts"], unit="s", utc=True)
    frame["time (UTC)"] = frame["at"].dt.strftime("%H:%M:%S")
    x = alt.X("at:T", title="UTC", scale=shell.UTC, axis=alt.Axis(format="%H:%M:%S", tickCount=6))
    base = alt.Chart(frame).encode(x=x)
    line = base.mark_line(strokeWidth=1.2).encode(
        y=alt.Y("mean_score:Q", title="mean score", scale=alt.Scale(zero=True)),
        # no `scale=None` here: that tells Vega the host address is itself a colour, and the lines vanish
        color=alt.Color("src_host:N", legend=alt.Legend(title=None, orient="top", direction="horizontal")),
        tooltip=["time (UTC)", "src_host", "queries", "alerts", "mean_score", "max_score"],
    )
    layers = [line]
    hit = frame[frame["alerts"] > 0]
    if not hit.empty:
        # Alert volume as bars on their own axis at the foot of the plot: how often each host crossed,
        # not another cloud of points on top of the score lines.
        layers.append(
            alt.Chart(hit)
            .mark_bar(size=6, color=p["signal"], opacity=0.35)
            .encode(
                x=x,
                y=alt.Y("alerts:Q", title=None, axis=alt.Axis(labelExpr="datum.value + ' alert(s)'")),
                tooltip=["time (UTC)", "src_host", "queries", "alerts", "max_score"],
            )
        )
    chart = alt.layer(*layers).resolve_scale(y="independent").properties(**shell.chart(210)).interactive()
    st.altair_chart(chart, width="stretch")
    st.caption(
        "Lines: mean model score per host per 10 s bucket. Bars along the foot: how many queries of that "
        "bucket crossed the threshold. Both share the x axis; the y axes are independent."
    )


def _feed(conn: sqlite3.Connection, view: dict) -> None:
    """Every alert the query matches, a page at a time.

    `alerts` is capped where it is read, so the feed does not use it: it asks SQLite for one page of the
    filtered, sorted set. A long capture holds far more alerts than any browser should be handed at once.
    """
    st.markdown('<div class="lm-sec">Alert feed</div>', unsafe_allow_html=True)
    cols = st.columns([2.1, 1.5, 1.6, 1.5, 1.3])
    search = cols[0].text_input(
        "Query name contains", key="lm_feed_search", help="Case-insensitive. `%` and `_` match themselves."
    )
    floor = cols[1].slider(
        "Minimum score", 0.0, 1.0, 0.0, 0.01, format="%.2f", key="lm_feed_score", help="Alert score, 0 to 1."
    )
    sort = cols[2].selectbox("Sort by", list(data.ALERT_SORTS), key="lm_feed_sort")
    size = cols[3].selectbox("Rows per page", [25, 50, 100, 250], index=1, key="lm_feed_rows")

    where = {"hosts": view["hosts"], "since": view["since"], "min_score": floor, "search": search}
    total = data.alert_page(conn, limit=0, **where)[1]
    pages = max(1, -(-total // size))
    page = min(cols[4].number_input("Page", 1, pages, 1, key="lm_feed_page"), pages)
    frame, _ = data.alert_page(conn, sort=sort, offset=(page - 1) * size, limit=size, **where)
    if not total:
        st.caption("No alert matches this window and these filters.")
        return
    first = (page - 1) * size + 1
    st.caption(
        f"Rows {first:,}-{first + len(frame) - 1:,} of {total:,} alerts"
        + ("" if size * pages >= total and total <= size else f" ({pages:,} pages at {size} rows)")
        + ", sorted by "
        + sort.lower()
        + "."
    )
    show = frame.copy()
    show["time"] = pd.to_datetime(show["ts"], unit="s", utc=True).dt.strftime("%H:%M:%S")
    show["why"] = show["features"].map(explain.headline)
    show["score"] = show["score"].map("{:.3f}".format)
    show = show[["id", "time", "src_host", "qname", "qtype", "score", "why"]].rename(
        columns={"src_host": "host", "qname": "query name", "qtype": "type"}
    )
    grid_key = f"lm_feed_grid_{page}_{size}"
    st.session_state["lm_feed_grid_key"] = grid_key
    st.session_state["lm_feed_ids"] = [int(i) for i in show["id"]]
    st.dataframe(
        show[["time", "host", "query name", "type", "score", "why"]],
        key=grid_key,
        hide_index=True,
        width="stretch",
        height=min(640, 96 + 36 * len(frame)),
        on_select="rerun",
        selection_mode="single-row",
        column_config={
            "time": st.column_config.TextColumn("time", width=88),
            "host": st.column_config.TextColumn("host", width=130),
            "query name": st.column_config.TextColumn("query name", width="large"),
            "type": st.column_config.TextColumn("type", width=70),
            "score": st.column_config.TextColumn("score", width=78, alignment="right"),
            "why": st.column_config.TextColumn("why", width="medium"),
        },
    )


def _open_clicked_alert() -> None:
    """Turn the feed's row selection into "this alert, in its own section".

    Called at the top of the page, before the tab strip exists: `live_section` is bound to the tabs widget, so
    the value has to be in place when the widget is created - setting it later raises, and a row click would
    otherwise show the alert but leave the user on the feed tab. The grid reports the click by rerunning the
    app, so this is one step from the user's side, with no page load.
    """
    key = st.session_state.get("lm_feed_grid_key")
    state = st.session_state.get(key) if key else None
    rows = (state or {}).get("selection", {}).get("rows") if isinstance(state, dict) else None
    if not rows:
        return
    ids = st.session_state.get("lm_feed_ids") or []
    index = int(rows[0])
    if 0 <= index < len(ids):
        st.session_state["lm_alert"] = ids[index]
        st.session_state["live_section"] = TRIGGER_TAB


def _clear_alert() -> None:
    """Forget the chosen alert and go back to the feed, in one step and without a page load.

    The grid's own selection goes too - a callback is allowed to write a widget's state, and if it stayed the
    next run would read the same click and put the alert straight back.
    """
    st.session_state.pop("lm_alert", None)
    st.session_state["live_section"] = "Alert feed"
    key = st.session_state.get("lm_feed_grid_key")
    if key:
        st.session_state[key] = {"selection": {"rows": [], "columns": [], "cells": []}}


def _why(conn: sqlite3.Connection) -> None:
    """One alert in full. Selected from the feed, so the default state is an invitation, not a guess.

    The alert is read by primary key rather than taken from a loaded slice: the row you clicked might be
    the 40,000th in the file.
    """
    p = shell.pal()
    st.markdown(f'<div class="lm-sec">{TRIGGER_TAB}</div>', unsafe_allow_html=True)
    alert_id = st.session_state.get("lm_alert")
    if alert_id is None:
        st.markdown(
            '<p class="lm-hint">'
            f"{shell.icon('pointer')}<span>Click a row in the feed above to see the features that put it over "
            "the threshold. Use the filters and sort to find the one you want.</span></p>",
            unsafe_allow_html=True,
        )
        return
    row = data.alert_by_id(conn, alert_id)
    if row is None:
        st.markdown(
            f'<p class="lm-hint">{shell.icon("alert")}<span>Alert {int(alert_id)} is not in this database - '
            "it was probably rewritten or truncated. Click another row.</span></p>",
            unsafe_allow_html=True,
        )
        return
    when = pd.to_datetime(row["ts"], unit="s", utc=True).strftime("%d %b %H:%M:%S UTC")
    # a query name is whatever the client sent, so it is escaped before it goes into the page's HTML
    qtype, model, host, qname = (
        html.escape(str(row.get(k) or "&ndash;")) for k in ("qtype", "model", "src_host", "qname")
    )
    caught = (
        f'<span class="lm-badge">caught {(row["detected_ts"] - row["ts"]) * 1000:,.0f} ms after the query</span>'
        if row.get("detected_ts")
        else ""
    )
    cols = st.columns([6, 1])
    cols[0].markdown(
        f'<p class="lm-note">alert {int(alert_id):,} - {when} - <span class="lm-badge">{qtype}</span> '
        f'<span class="lm-badge is-alert">score {float(row["score"]):.3f} over threshold '
        f'{float(row["threshold"]):.4f}</span> <span class="lm-badge">{model}</span> {caught}</p>'
        f'<p class="lm-wire">{host} &rarr; {qname}</p>',
        unsafe_allow_html=True,
    )
    cols[1].button("Clear", key="lm_alert_clear", on_click=_clear_alert, help="Back to the empty prompt.")

    features = [f for f in row["features"] if isinstance(f, dict) and f.get("feature")]
    if not features:
        st.caption("This scorer stored no explanation, so the alert has only its score.")
        return
    left, right = st.columns([1, 1.15])
    bars = (
        alt.Chart(pd.DataFrame(features))
        .mark_bar(size=16)
        .encode(
            y=alt.Y("feature:N", sort="-x", axis=None, title=None),
            x=alt.X("shap:Q", title="SHAP contribution (log-odds)"),
            color=alt.Color("shap:Q", scale=alt.Scale(domain=[-1, 1], range=[p["fade"], p["signal"]]), legend=None),
            tooltip=["feature", "value", "shap"],
        )
        .properties(height=min(240, 34 * len(features) + 20), **shell.chart_config())
    )
    left.altair_chart(bars, width="stretch")
    parts = []
    for feat in features:
        name = str(feat["feature"])
        label = html.escape(explain.label(name))
        reading = html.escape(explain.value_text(name, feat.get("value")))
        meaning = html.escape(explain.meaning(name, feat.get("shap")))
        parts.append(
            f'<div><p class="lm-why"><strong>{label}</strong> {reading}</p><p class="lm-kv">{meaning}</p></div>'
        )
    lines = "".join(parts)
    right.markdown(f'<div class="lm-dl">{lines}</div>', unsafe_allow_html=True)


def _latency(batches: pd.DataFrame, meta: dict) -> None:
    p = shell.pal()
    st.markdown(
        '<div class="lm-sec">Processing latency</div>'
        '<p class="lm-note">From the <code>batches</code> table: features, scoring and explanations '
        "for each scored batch.</p>",
        unsafe_allow_html=True,
    )
    if batches.empty:
        st.caption(
            "No `batches` table in this database: it was written before 19 Nov. Run the sniffer again, or see "
            "`results/latency_cpu.csv` for each model timed on one CPU (`python scripts/time_models.py`)."
        )
        return
    frame = batches[batches["queries"] > 0].copy()
    frame["ms_per_query"] = frame["process_ms"] / frame["queries"]
    ms = _median_per_query(batches)
    p95 = float(frame["ms_per_query"].quantile(0.95))
    cols = st.columns(3)
    cols[0].metric("median", f"{ms:.2f} ms", help="median of per-query time across batches")
    cols[1].metric("95th percentile", f"{p95:.2f} ms")
    cols[2].metric(
        "10 ms rule",
        "pass" if ms < data.LIMIT_MS else "over",
        delta_color="off",
        help=f"the selection rule: at most {data.LIMIT_MS:.0f} ms per query (README, Models)",
    )
    hist = (
        alt.Chart(frame)
        .mark_bar(color="#6E7781")
        .encode(
            x=alt.X(
                "ms_per_query:Q",
                bin=alt.Bin(maxbins=18),
                title="ms per query",
                axis=alt.Axis(tickCount=6, format=".1f"),
                scale=alt.Scale(zero=True),
            ),
            y=alt.Y("count()", title="batches"),
            tooltip=["queries", "process_ms", "ms_per_query"],
        )
    )
    rule = alt.Chart(pd.DataFrame({"limit": [data.LIMIT_MS]})).mark_rule(color=p["signal"]).encode(x="limit:Q")
    st.altair_chart(alt.layer(hist, rule).properties(**shell.chart(210)), width="stretch")
    mode = str(meta.get("mode", ""))
    if mode == "replay":
        st.caption(
            "`meta.mode = replay`: the source was a capture file, so packet times are not wall-clock "
            "and time-to-alert is not meaningful here. Scores and latency still are."
        )
    elif mode == "sniff":
        st.caption(
            "`meta.mode = sniff`: these packets were live, so `detected_ts - ts` in the feed is a real time to alert."
        )


def _median_per_query(batches: pd.DataFrame) -> float:
    frame = batches[batches["queries"] > 0]
    if frame.empty:
        return float("nan")
    return float((frame["process_ms"] / frame["queries"]).median())
