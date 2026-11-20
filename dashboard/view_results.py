"""Results page: the frozen experiment numbers, from the CSVs `python -m eval.summarise` writes.

Six things, because those are the six the card names: the model comparison table, ROC curves,
confusion matrices, the latency chart, the Experiment 3 per-tool view, and the shuffled-vs-time gap.
Numbers are read, never recomputed, so the page cannot drift from `results/summary.csv`.
"""

from __future__ import annotations

import altair as alt
import pandas as pd
import streamlit as st

from dashboard import data, shell

MODEL_ORDER = ["m1", "rf", "iforest", "m2", "m3_cnn", "m3_bilstm"]


TABLE_COLS = ["model", "picked", "recall", "precision", "f1", "fpr", "roc_auc", "recall_at_1pct_fpr", "fp", "fn"]


def render() -> None:
    summary = data.read_table("summary")
    shell.masthead(
        "leakmate / frozen results",
        "Results",
        "Every model and experiment as scored at the results freeze. Nothing on this page is recalculated: "
        "it reads the summarise output directly.",
    )
    if summary.empty:
        shell.need(
            "No `results/summary.csv` here.",
            "Build it from the committed results files: `python -m eval.summarise` (writes "
            "`results/summary.csv`, `selection.csv`, `per_tool.csv`, `latency.csv` and `results/figures/`).",
        )
        return

    variants = st.toggle(
        "Show host-averaged and ablation runs",
        value=False,
        help="Variants such as m2_hostavg or m1_ablation_cic_leaky are ablations, not the six headline models.",
    )
    summary = _filter_variants(summary, variants)
    selection = data.read_table("selection")
    _strip(summary, selection)

    experiment = st.selectbox(
        "Experiment",
        options=list(summary["experiment"].unique()),
        format_func=data.experiment_label,
        index=_default_experiment(summary["experiment"]),
    )
    shell.key()
    compare, curves, latency, tools, split = st.tabs(
        ["Comparison", "ROC and matrices", "Latency", "Per tunnel tool", "Split order"]
    )
    with compare:
        _comparison(summary, selection, experiment)
        _trade_off(summary, experiment)
    with curves:
        _curves(summary, experiment)
    with latency:
        _latency(summary)
    with tools:
        _per_tool(summary, variants)
    with split:
        _split_gap(summary)


# --------------------------------------------------------------------------- pieces


def _filter_variants(frame: pd.DataFrame, keep: bool) -> pd.DataFrame:
    """Host-averaged and ablation runs are rows of their own in the CSVs; hide them unless asked."""
    return frame if keep else data.drop_variants(frame)


def _default_experiment(experiments) -> int:
    names = list(experiments)
    return names.index("E1") if "E1" in names else 0


def _strip(summary: pd.DataFrame, selection: pd.DataFrame) -> None:
    picked = str(selection.iloc[0]["selected_model"]) if not selection.empty else "n/a"
    cells = [
        ("runs", f"{len(summary):,}", False),
        ("models", f"{summary['model'].nunique()}", False),
        ("experiments", f"{summary['experiment'].nunique()}", False),
        ("results set", data.results_dir().name, False),
        ("frozen at", "tag results-freeze", False),
    ]
    shell.strip(cells)
    if picked != "n/a":
        name = data.results_dir().name
        st.caption(
            f"The rule is applied per experiment in `{name}/selection.csv`; the model it picked for the "
            "experiment below is marked in the table."
        )
        if name == "results":
            st.caption(
                "Experiments 1, 3 and 5 here use the original testbed names, where every tunnel name ends in "
                "`tunnel.test`, so a model that reads names scores perfectly from the suffix. For those "
                "experiments quote the runs with the domain hidden: `LEAKMATE_RESULTS=results_nozone` "
                "(docs/suffix-ablation.md)."
            )


def _comparison(summary: pd.DataFrame, selection: pd.DataFrame, experiment: str) -> None:
    st.markdown(
        f'<div class="lm-sec">Model comparison - {data.experiment_label(experiment)}</div>'
        '<p class="lm-note">Sorted by F1. "picked" marks the model <code>selection.csv</code> chose for this '
        "experiment under the rule: best F1 with a false-positive rate of at most 1% and at most 10 ms per "
        "query; an F1 tie goes to the faster model.</p>",
        unsafe_allow_html=True,
    )
    frame = summary[summary["experiment"] == experiment].copy()
    if frame.empty:
        st.caption("No runs for this experiment in this results set.")
        return
    winner = _winner(selection, experiment)
    frame["model"] = frame["model"].map(data.model_label)
    frame["picked"] = frame["model"].map(lambda m: "picked" if winner and data.model_label(winner) == m else "")
    frame = frame.sort_values(["f1", "recall"], ascending=False)
    show = frame[TABLE_COLS].copy()
    for col in ("recall", "precision", "f1", "roc_auc", "recall_at_1pct_fpr"):
        show[col] = show[col].map("{:.4f}".format)
    show["fpr"] = show["fpr"].map("{:.5f}".format)
    show = show.rename(
        columns={
            "picked": "rule",
            "roc_auc": "ROC-AUC",
            "fpr": "false-positive rate",
            "recall_at_1pct_fpr": "recall @ 1% FPR",
            "fp": "false pos.",
            "fn": "missed",
        }
    )
    shell.table(
        show,
        [
            ("model", "model", "text"),
            ("rule", "rule", "mark"),
            ("recall", "recall", "num"),
            ("precision", "precision", "num"),
            ("f1", "f1", "num"),
            ("false-positive rate", "false-positive rate", "num"),
            ("ROC-AUC", "ROC-AUC", "num"),
            ("recall @ 1% FPR", "recall @ 1% FPR", "num"),
            ("false pos.", "false pos.", "num"),
            ("missed", "missed", "num"),
        ],
        picked=_picked_label(show["model"], selection, experiment),
    )


def _picked_label(models, selection: pd.DataFrame, experiment: str) -> str | None:
    """The display label of the model `selection.csv` chose, if it appears in this table at all."""
    winner = _winner(selection, experiment)
    if not winner:
        return None
    label = data.model_label(winner)
    return label if label in set(models) else None


def _winner(selection: pd.DataFrame, experiment: str) -> str | None:
    if selection.empty:
        return None
    row = selection[selection["experiment"] == experiment]
    return None if row.empty else str(row.iloc[0]["selected_model"])


def _trade_off(summary: pd.DataFrame, experiment: str) -> None:
    p = shell.pal()
    st.markdown(
        '<div class="lm-sec">Detection against processing cost</div>'
        '<p class="lm-note">Research question 1 asks which model gives the best trade-off between detection, '
        "false positives and speed. Recall at 1% false positives does not depend on a model's threshold, so "
        "it still separates models when F1 is saturated.</p>",
        unsafe_allow_html=True,
    )
    frame = summary[summary["experiment"] == experiment].copy()
    if frame.empty or "recall_at_1pct_fpr" not in frame:
        return
    frame = frame.dropna(subset=["latency_ms_per_query", "recall_at_1pct_fpr"])
    # family first: it is derived from the raw model name, which is about to be prettified for display
    frame["family"] = frame["model"].map(shell.family)
    frame["model"] = frame["model"].map(data.model_label)
    frame["cost"] = (frame["latency_ms_per_query"] > data.LIMIT_MS).map(
        {True: "over the rule", False: "under the rule"}
    )
    scale = alt.Scale(domain=list(shell.FAMILIES), range=list(shell.FAMILIES.values()))
    pts = (
        alt.Chart(frame)
        .mark_point(size=95, filled=True)
        .encode(
            x=alt.X(
                "latency_ms_per_query:Q",
                title="ms per query",
                scale=alt.Scale(type="log", nice=True),
                axis=alt.Axis(format="~g", tickCount=5),
            ),
            y=alt.Y(
                "recall_at_1pct_fpr:Q",
                title="recall at 1% false positives",
                scale=alt.Scale(zero=False, nice=True),
            ),
            # colour says the model family, shape says whether it clears the latency rule; the key sits
            # above the tabs, so nothing is drawn over the points
            color=alt.Color("family:N", scale=scale, legend=None),
            shape=alt.Shape(
                "cost:N",
                scale=alt.Scale(domain=["under the rule", "over the rule"], range=["circle", "square"]),
                legend=None,
            ),
            tooltip=["model", "family", "latency_ms_per_query", "recall_at_1pct_fpr", "fpr", "f1", "roc_auc"],
        )
    )
    rule = (
        alt.Chart(pd.DataFrame({"limit": [data.LIMIT_MS]}))
        .mark_rule(color=p["ink2"], strokeDash=[4, 3])
        .encode(x="limit:Q")
    )
    st.altair_chart(alt.layer(pts, rule).properties(**shell.chart(240)), width="stretch")
    st.caption(
        f"Colour is the model family; a square sits where measured cost passes the {data.LIMIT_MS:.0f} ms rule "
        "(dashed) and a circle where it clears it. A flat top edge means the experiment is saturated: several "
        "models separate every query, and cost is what tells them apart."
    )


def _curves(summary: pd.DataFrame, experiment: str) -> None:
    st.markdown('<div class="lm-sec">Curves and matrices</div>', unsafe_allow_html=True)
    roc = data.figure("roc", experiment=experiment)
    models = summary.loc[summary["experiment"] == experiment, "model"].tolist()
    cols = st.columns([1.15, 1])
    if roc:
        cols[0].image(str(roc), caption=f"ROC curves, {data.experiment_label(experiment).lower()}")
    else:
        cols[0].caption(
            f"No `{data.results_dir().name}/figures/roc_{experiment}.png` - `python -m eval.summarise --results-dir "
            f"{data.results_dir().name}` draws it (without `--no-plots`)."
        )
    if models:
        model = cols[1].selectbox("Confusion matrix", models, format_func=data.model_label)
        cm = data.figure("cm", model=model, experiment=experiment)
        if cm:
            cols[1].image(str(cm), caption=f"{data.model_label(model)}, {experiment}")
        else:
            cols[1].caption(f"No `{data.results_dir().name}/figures/cm_{model}_{experiment}.png`.")


def _latency(summary: pd.DataFrame) -> None:
    p = shell.pal()
    st.markdown(
        '<div class="lm-sec">Latency</div>'
        '<p class="lm-note">One query at a time. The selection rule allows at most 10 ms per query.</p>',
        unsafe_allow_html=True,
    )
    latency = data.read_table("latency")
    if latency.empty:
        latency = (
            summary.groupby("model", as_index=False)["latency_ms_per_query"]
            .median()
            .rename(columns={"latency_ms_per_query": "latency_ms_median"})
        )
    frame = data.drop_variants(latency).copy()
    frame["family"] = frame["model"].map(shell.family)
    frame["model"] = frame["model"].map(data.model_label)
    frame["over"] = frame["latency_ms_median"] > data.LIMIT_MS
    scale = alt.Scale(domain=list(shell.FAMILIES), range=list(shell.FAMILIES.values()))
    bars = (
        alt.Chart(frame)
        .mark_bar(size=18)
        .encode(
            x=alt.X("model:N", title=None, sort=sorted(frame["model"])),
            y=alt.Y("latency_ms_median:Q", title="ms per query"),
            color=alt.Color(
                "family:N",
                legend=alt.Legend(title=None, direction="horizontal"),
                scale=scale,
            ),
            tooltip=["model", "family", "latency_ms_median", "queries_per_sec"],
        )
    )
    rule = (
        alt.Chart(pd.DataFrame({"limit": [data.LIMIT_MS]}))
        .mark_rule(color=p["ink"], strokeDash=[4, 3])
        .encode(y="limit:Q")
    )
    st.altair_chart((bars + rule).properties(**shell.chart(240)), width="stretch")
    st.caption(
        f"Red is under the rule; grey is over. Median over each model's runs, from "
        f"`{data.results_dir().name}/latency.csv`. The selection uses `latency_cpu.csv`, every model timed on "
        "one CPU (`python scripts/time_models.py`)."
    )


def _per_tool(summary: pd.DataFrame, variants: bool) -> None:
    p = shell.pal()
    st.markdown(
        '<div class="lm-sec">Per tunnel tool</div>'
        '<p class="lm-note">Recall of each tool the model was trained on, and of the one it never saw - '
        "Experiment 3 for all four held-out tools at once, so the experiment selector above does not change "
        "this panel; the variants toggle does. This is where a supervised model's honesty is tested: "
        "dns2tcp and dnscat2 barely resemble each other.</p>",
        unsafe_allow_html=True,
    )
    per_tool = data.read_table("per_tool")
    if per_tool.empty:
        st.caption("No `results/per_tool.csv` - run `python -m eval.summarise`.")
        return
    frame = _filter_variants(per_tool, variants)
    frame = frame[frame["experiment"].isin(["E1", "E3_dnscat2", "E3_dns2tcp", "E3_dnsexfiltrator", "E3_iodine"])]
    if frame.empty:
        return
    frame["model"] = frame["model"].map(data.model_label)
    frame["held out"] = frame["experiment"].map(lambda e: "no" if e == "E1" else e.replace("E3_", ""))
    chart = (
        alt.Chart(frame)
        .mark_rect()
        .encode(
            x=alt.X("tool:N", title=None),
            y=alt.Y("model:N", title=None, sort=sorted(frame["model"].unique(), reverse=True)),
            color=alt.Color(
                "recall:Q",
                scale=alt.Scale(domain=[0, 1], range=["#221F31", p["signal"]]),
                legend=alt.Legend(title="recall"),
            ),
            row=alt.Row("held out:N", title="tool held out of training", header=alt.Header(labelFontSize=11)),
            tooltip=["model", "tool", "recall", "held out"],
        )
        .properties(height=140)
    )
    st.altair_chart(chart.resolve_scale(color="independent").configure_view(strokeWidth=0), width="stretch")
    st.caption(
        "Each panel hides one tool from training (Experiment 3); the row that collapses is the tool the "
        "model never met."
    )


def _split_gap(summary: pd.DataFrame) -> None:
    p = shell.pal()
    st.markdown(
        '<div class="lm-sec">Shuffled against time split</div>'
        '<p class="lm-note">How much better M1 looks if rows are shuffled at random instead of split by time. '
        "Pairs from docs/experiment-s.md: CIC is Experiment 2 against Experiment S, the testbed is Experiment 1 "
        "against its shuffled rerun.</p>",
        unsafe_allow_html=True,
    )
    # docs/experiment-s.md: CIC time = E2, CIC shuffled = S; testbed time = E1, shuffled = S (tag testbed)
    pairs = [
        ("CIC", "time", "m1", "E2"),
        ("CIC", "shuffled", "m1", "S"),
        ("Testbed", "time", "m1", "E1"),
        ("Testbed", "shuffled", "m1_testbed", "S"),
    ]
    rows = []
    for dataset, split, model, experiment in pairs:
        row = summary[(summary["model"] == model) & (summary["experiment"] == experiment)]
        if row.empty:
            continue
        r = row.iloc[0]
        rows.append(
            {
                "dataset": dataset,
                "split": split,
                "f1": r["f1"],
                "fpr": r["fpr"],
                "roc_auc": r["roc_auc"],
                "recall_at_1pct_fpr": r["recall_at_1pct_fpr"],
            }
        )
    frame = pd.DataFrame(rows, columns=["dataset", "split", "f1", "fpr", "roc_auc", "recall_at_1pct_fpr"])
    # a pair needs both halves: results_nozone has the time-split Experiment 1 run but no shuffled rerun
    paired = frame.groupby("dataset")["split"].transform("nunique") == 2
    frame = frame[paired]
    if frame.empty:
        st.caption(f"`{data.results_dir().name}/` has no shuffled runs (Experiment S); they are in `results/`.")
        return
    gap = frame.pivot_table(index="dataset", columns="split", values="f1", aggfunc="first")
    chart = (
        alt.Chart(
            frame.melt(
                id_vars=["dataset", "split"], value_vars=["f1", "fpr", "roc_auc"], value_name="value", var_name="metric"
            )
        )
        .mark_bar(size=16)
        .encode(
            x=alt.X("metric:N", title=None),
            y=alt.Y("value:Q", title=None, axis=alt.Axis(format=".3f")),
            color=alt.Color(
                "split:N",
                scale=alt.Scale(domain=["time", "shuffled"], range=[p["ink2"], p["signal"]]),
                legend=alt.Legend(title=None, orient="top", direction="horizontal"),
            ),
            column=alt.Column("dataset:N", title=None),
            tooltip=["dataset", "split", "metric", "value"],
        )
        .properties(height=200)
    )
    st.altair_chart(chart, width="stretch")
    for dataset in gap.index:
        delta = float(gap.loc[dataset, "shuffled"] - gap.loc[dataset, "time"])
        st.caption(
            f"{dataset}: F1 moves {delta:+.4f} when the split is shuffled. Both are saturated at 1.0, so there "
            "is no headroom to inflate - the reading is in docs/experiment-s.md."
        )
