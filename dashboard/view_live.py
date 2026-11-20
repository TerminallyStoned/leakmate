"""Live page: what the detector is seeing right now, and why it alerted.

Built against `live/alerts.db` as documented in live/README.md: `alerts`, `host_stats`, `batches`
(19 Nov, PR #47) and `meta`. Every panel degrades to a message naming the command that fills it.
"""

from __future__ import annotations

import html

import altair as alt
import pandas as pd
import streamlit as st

from dashboard import data, explain, shell


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
        _strip(meta, alerts, stats, batches, view["note"])
        feed, trend, why, latency = st.tabs(["Alert feed", "Score over time", "Why it fired", "Latency"])
        with trend:
            _score_over_time(stats, alerts)
        with feed:
            _feed(alerts)
        with why:
            _detail(alerts)
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


def _strip(meta: dict, alerts: pd.DataFrame, stats: pd.DataFrame, batches: pd.DataFrame, note: str) -> None:
    queries = int(stats["queries"].sum()) if not stats.empty and "queries" in stats else 0
    alerting = alerts["src_host"].nunique() if not alerts.empty else 0
    hosts = max(stats["src_host"].nunique() if not stats.empty else 0, 0)
    rate = (len(alerts) / queries * 100) if queries else 0.0
    cells = [
        ("model", html.escape(str(meta.get("model", "unknown"))), False),
        ("threshold", _num(meta.get("threshold")), False),
        ("queries scored", f"{queries:,}", False),
        ("alerts", f"{len(alerts):,}", bool(alerts.size)),
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
    frame = frame[frame["src_host"].isin(top)]
    axis = alt.Axis(format="%H:%M:%S", tickCount=6)
    base = alt.Chart(frame).encode(x=alt.X("bucket_ts:T", title=None, axis=axis))
    line = base.mark_line(strokeWidth=1.2).encode(
        y=alt.Y("mean_score:Q", title="mean score", scale=alt.Scale(zero=True)),
        color=alt.Color("src_host:N", legend=alt.Legend(title=None, orient="top", direction="horizontal"), scale=None),
        tooltip=["bucket_ts", "src_host", "queries", "alerts", "mean_score", "max_score"],
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
                x=alt.X("bucket_ts:T", axis=axis),
                y=alt.Y("alerts:Q", title=None, axis=alt.Axis(labelExpr="datum.value + ' alert(s)'")),
                tooltip=["bucket_ts", "src_host", "queries", "alerts", "max_score"],
            )
        )
    chart = alt.layer(*layers).resolve_scale(y="independent").properties(**shell.chart(210)).interactive()
    st.altair_chart(chart, use_container_width=True)
    st.caption(
        "Lines: mean model score per host per 10 s bucket. Bars along the foot: how many queries of that "
        "bucket crossed the threshold. Both share the x axis; the y axes are independent."
    )


def _feed(alerts: pd.DataFrame) -> None:
    st.markdown(
        '<div class="lm-sec">Alert feed</div>'
        '<p class="lm-note">Newest first. The last column is the strongest feature of that alert, in words.</p>',
        unsafe_allow_html=True,
    )
    if alerts.empty:
        st.caption("Nothing crossed the threshold in this database.")
        return
    frame = alerts.sort_values("id", ascending=False).head(250).copy()
    frame["time"] = pd.to_datetime(frame["ts"], unit="s", utc=True).dt.strftime("%H:%M:%S")
    frame["why"] = frame["features"].map(explain.headline)
    frame["score"] = frame["score"].map("{:.3f}".format)
    show = frame[["time", "src_host", "qname", "qtype", "score", "why"]].rename(
        columns={"src_host": "host", "qname": "query name", "qtype": "type", "score": "score"}
    )
    shell.table(
        show,
        [
            ("time", "time", "text"),
            ("host", "host", "text"),
            ("query name", "query name", "wire"),
            ("type", "type", "text"),
            ("score", "score", "num"),
            ("why", "why", "text"),
        ],
        max_rows=250,
    )


def _detail(alerts: pd.DataFrame) -> None:
    p = shell.pal()
    st.markdown('<div class="lm-sec">Why this alert fired</div>', unsafe_allow_html=True)
    if alerts.empty:
        st.caption("Select an alert once the feed has rows.")
        return
    frame = alerts.sort_values("id", ascending=False)
    picked = st.selectbox(
        "Alert",
        options=list(frame["id"]),
        format_func=lambda i: _alert_caption(frame, i),
        label_visibility="collapsed",
    )
    row = frame[frame["id"] == picked].iloc[0]
    when = pd.to_datetime(row["ts"], unit="s", utc=True).strftime("%d %b %H:%M:%S UTC")
    # a query name is whatever the client sent, so it is escaped before it goes into the page's HTML
    qtype, model, host, qname = (html.escape(str(row[k])) for k in ("qtype", "model", "src_host", "qname"))
    st.markdown(
        f'<p class="lm-note">{when} - <span class="lm-badge">{qtype}</span> '
        f'<span class="lm-badge is-alert">score {row["score"]:.3f} over threshold {row["threshold"]:.4f}</span> '
        f'<span class="lm-badge">{model}</span></p>'
        f'<p class="lm-wire">{host} &rarr; {qname}</p>',
        unsafe_allow_html=True,
    )
    features = [f for f in row["features"] if f.get("feature")]
    if not features:
        st.caption("This scorer stored no explanation, so the alert has only its score.")
        return
    with st.container():
        left, right = st.columns([1, 1.15])
        bars = (
            alt.Chart(pd.DataFrame(features))
            .mark_bar(size=16)
            .encode(
                y=alt.Y("feature:N", sort="-x", axis=None, title=None),
                x=alt.X("shap:Q", title="SHAP contribution (log-odds)"),
                color=alt.Color("shap:Q", scale=alt.Scale(domain=[-1, 1], range=["#6E7781", p["signal"]]), legend=None),
                tooltip=["feature", "value", "shap"],
            )
            .properties(height=min(240, 34 * len(features) + 20), **shell.chart_config())
        )
        left.altair_chart(bars, use_container_width=True)
        lines = "".join(
            f'<div><p class="lm-why"><strong>{html.escape(explain.label(f["feature"]))}</strong> '
            f"{html.escape(explain.value_text(f['feature'], f.get('value')))}</p>"
            f'<p class="lm-kv">{html.escape(explain.meaning(f["feature"], f.get("shap")))}</p></div>'
            for f in features
        )
        right.markdown(f'<div class="lm-dl">{lines}</div>', unsafe_allow_html=True)


def _alert_caption(frame: pd.DataFrame, alert_id) -> str:
    row = frame[frame["id"] == alert_id].iloc[0]
    qname = row["qname"] if len(row["qname"]) <= 46 else row["qname"][:43] + "..."
    return f"{pd.to_datetime(row['ts'], unit='s', utc=True).strftime('%H:%M:%S')}  {row['src_host']}  {qname}"


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
    st.altair_chart(alt.layer(hist, rule).properties(**shell.chart(210)), use_container_width=True)
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
