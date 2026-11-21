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

    shell.verdicts(_conclusions())

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
        shell.section("Evaluation", f"from <code>{data.results_dir().name}/</code> at tag <code>results-freeze</code>")
        shell.strip(results["cells"])
        _picks(results["selection"])
        _latency_overview(results["latency"])


# --------------------------------------------------------------------------- live side


def _live_summary() -> dict:
    empty = {"cells": [("live data", "none", True)], "buckets": pd.DataFrame(), "hosts": pd.DataFrame(), "latest": None}
    conn = data.connect()
    if conn is None:
        return empty
    try:
        meta = data.read_meta(conn)
        alerts = data.read_alerts(conn)
        total_alerts = data.alert_counts(conn)["alerts"]
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
        ("alerts", f"{total_alerts:,}", bool(total_alerts)),
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
            .sort_values(["alerts", "queries"], ascending=False)
            .head(8)
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
    frame["time (UTC)"] = frame["at"].dt.strftime("%H:%M")
    x = alt.X("at:T", title="UTC", scale=shell.UTC, axis=alt.Axis(format="%H:%M", labelFontSize=10, titleFontSize=10))
    bars = (
        alt.Chart(frame)
        .mark_bar(color=p["signal"])
        .encode(x=x, y=alt.Y("alerts:Q", title="alerts"), tooltip=["time (UTC)", "queries", "alerts"])
    )
    quiet = (
        alt.Chart(frame)
        .mark_bar(color=p["fade"])
        .encode(x=x, y=alt.Y("queries:Q", title=None), tooltip=["time (UTC)", "queries"])
    )
    st.altair_chart(alt.layer(quiet, bars).properties(**shell.chart(132)), width="stretch")
    per = f"{bucket_s / 60:g} min" if bucket_s < 3_600 else f"{bucket_s / 3_600:g} h"
    st.caption(f"Grey: queries scored per {per}. Purple: of those, the alerts.")


def _top_hosts(hosts: pd.DataFrame) -> None:
    """Up to eight hosts, alerting first, as a table: a bar chart this short dropped every other host label,
    and a host with no alerts had no bar at all, so benign hosts vanished."""
    if hosts.empty:
        return
    frame = hosts.copy()
    frame["flagged"] = (frame["alerts"] / frame["queries"].clip(lower=1)).map("{:.1%}".format)
    frame["queries"] = frame["queries"].map("{:,}".format)
    frame["alerts"] = frame["alerts"].map("{:,}".format)
    shell.table(
        frame,
        [
            ("src_host", "host", "wire"),
            ("queries", "queries", "num"),
            ("alerts", "alerts", "num"),
            ("flagged", "flagged", "num"),
        ],
    )


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
    selection = data.read_selection()
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
            ("picked", "picked", "text"),
            ("f1", "F1", "num"),
            ("fpr", "FPR", "num"),
            ("ms/query", "ms/query", "num"),
        ],
    )
    name = data.results_dir().name
    st.caption(
        "`selection.csv`: the model the rule picked for each experiment. The rule is the best F1 with a "
        "false-positive rate (FPR) of at most 1% and at most 10 ms per query."
    )
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
            "Experiments 1, 3 and 5 come from `results_nozone/`, the runs with the lab domain hidden: on the "
            "original names every tunnel ends in `tunnel.test`, so a model that reads names wins from the suffix "
            "(docs/suffix-ablation.md). Experiments 2 and 4 use CIC and come from `results/`."
        )


def _latency_overview(latency: pd.DataFrame) -> None:
    p = shell.pal()
    if latency.empty:
        return
    frame = data.drop_variants(latency).copy()
    frame["family"] = frame["model"].map(shell.family)
    frame["model"] = frame["model"].map(data.model_label)
    frame["under"] = frame["latency_ms_median"] < data.LIMIT_MS
    chart = (
        alt.Chart(frame)
        .mark_bar(size=12)
        .encode(
            # one row per model: slanted labels under a half-width chart collided and Vega hid every other one
            y=alt.Y(
                "model:N",
                title=None,
                sort=sorted(frame["model"]),
                axis=alt.Axis(labelLimit=140, labelFontSize=10, labelOverlap=False),
            ),
            x=alt.X("latency_ms_median:Q", title="ms per query", axis=alt.Axis(tickCount=4)),
            color=alt.Color(
                "under:N", scale=alt.Scale(domain=[True, False], range=[p["signal"], p["fade"]]), legend=None
            ),
            tooltip=["model", "latency_ms_median"],
        )
    )
    rule = (
        alt.Chart(pd.DataFrame({"limit": [data.LIMIT_MS]}))
        .mark_rule(color=p["ink2"], strokeDash=[4, 3])
        .encode(x="limit:Q")
    )
    height = 26 * len(frame)
    st.altair_chart(alt.layer(chart, rule).properties(**shell.chart(height)), width="stretch")
    st.caption(f"Purple is under the {data.LIMIT_MS:.0f} ms rule (dashed). Median of three timings on one CPU box.")


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


# --------------------------------------------------------------------------- conclusions


def _conclusions() -> list[dict]:
    """Five cards: the questions the frozen tables answer, and the answer.

    Nothing is typed in. Models, experiments, scores, recalls and timings come from `results/summary.csv`,
    `results/selection.csv` and `results/latency.csv`, the latency gate from `data.LIMIT_MS`, and the machine
    the timings ran on from `results/latency_cpu.csv`. Written by hand is only the question each card asks (its
    kicker) and the plain reading of the number.
    """
    summary = data.read_table("summary")
    selection = data.read_selection()
    latency = data.read_table("latency")
    if summary.empty:
        return [
            {
                "icon": "warn",
                "tone": "tone-warn",
                "kicker": "No frozen results",
                "hero": "Run eval.summarise",
                "detail": "The dashboard reads results/*.csv and computes nothing itself.",
            }
        ]
    out: list[dict] = []
    headline = data.drop_variants(summary)

    best = headline.loc[headline["f1"].idxmax()]
    out.append(
        {
            "icon": "ok",
            "tone": "tone-good",
            "kicker": "Top F1",
            "hero": data.model_label(best["model"]),
            "detail": f"F1 {best['f1']:.4f} at {best['fpr']:.2%} FPR in "
            f"{data.experiment_label(best['experiment']).lower()}.",
        }
    )

    if not selection.empty:
        counts = selection["selected_model"].value_counts()
        top_model, top_n = counts.index[0], int(counts.iloc[0])
        out.append(
            {
                "icon": "trend",
                "tone": "tone-good",
                "kicker": "Rule picks",
                "hero": data.model_label(top_model),
                "detail": f"Chosen in {top_n} of {len(selection)} experiments by best F1 subject to the "
                f"false-positive ceiling and the {data.LIMIT_MS:.0f} ms per-query gate.",
            }
        )

    held_out = headline[headline["experiment"].str.startswith("E3")].sort_values("recall")
    if not held_out.empty:
        worst = held_out.iloc[0]
        out.append(
            {
                "icon": "alert",
                "tone": "tone-alert",
                "kicker": "Held-out tool",
                "hero": f"{worst['recall']:.1%}",
                "detail": f"{data.model_label(worst['model'])} catches this much "
                f"{worst['experiment'].removeprefix('E3_')} traffic when that tool is unseen in training, "
                f"against {worst['f1']:.4f} F1 there.",
            }
        )

    cross = headline[headline["experiment"] == "E4_cic2testbed"]
    # the rule's ceiling first: the top F1 here (M2) flags 13% of benign traffic, which the rule rejects
    cross = cross[cross["fpr"] <= data.MAX_FPR].sort_values("f1")
    if not cross.empty:
        c = cross.iloc[-1]
        out.append(
            {
                "icon": "warn",
                "tone": "tone-warn",
                "kicker": "Cross-dataset",
                "hero": f"{c['recall']:.1%}",
                "detail": f"{data.model_label(c['model'])} recall at {c['fpr']:.2%} FPR on "
                f"{data.experiment_label('E4_cic2testbed').lower()}, the best F1 within the {data.MAX_FPR:.0%} "
                "false-positive ceiling: a network it was never trained on, the only experiment not saturated.",
            }
        )

    per_tool = data.read_table("per_tool")
    if not per_tool.empty:
        by_tool = per_tool.groupby("tool")["recall"].mean().sort_values()
        tool, score = by_tool.index[0], float(by_tool.iloc[0])
        runs = int((per_tool["tool"] == tool).sum())
        n_tools = per_tool["tool"].nunique()
        out.append(
            {
                "icon": "target",
                "tone": "tone-warn",
                "kicker": "Hardest tool",
                "hero": tool,
                "detail": f"Mean recall {score:.1%} across {runs} model-and-experiment runs that saw it, the "
                f"lowest of the {n_tools} tools measured. A detector that misses this one is "
                "measurably blind to a whole client, not merely slower on it.",
            }
        )

    if not latency.empty:
        under = latency[latency["latency_ms_median"] < data.LIMIT_MS]["model"].nunique()
        cpu = data.read_table("latency_cpu")
        box = str(cpu["cpu"].iloc[0]).replace(" Processor", "") if not cpu.empty else "one CPU box"
        out.append(
            {
                "icon": "clock",
                "tone": "tone-warn",
                "kicker": "Latency gate",
                "hero": f"{under} of {latency['model'].nunique()}",
                "detail": f"Timed models holding median under {data.LIMIT_MS:.0f} ms per query on one core of "
                f"a {box}. The gate is what removes candidates that win on accuracy alone.",
            }
        )
    return out
