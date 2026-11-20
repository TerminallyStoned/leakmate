"""Page furniture shared by the three pages: theme, navigation, masthead, strips, tables.

One source of colour and type, so the pages read as one product. Light only: Streamlit resolves its theme
when the server starts and cannot change it at runtime, so the dashboard owns one palette and the charts read
it from here rather than from module constants.
"""

from __future__ import annotations

import html

from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

HERE = Path(__file__).resolve().parent
#: x scale for every time axis. Vega draws times in the browser's zone unless told otherwise, and the feed,
#: the captions and live/README.md are all in UTC.
UTC = alt.Scale(type="utc")

#: chart colours, matching the custom properties in styles.css
PALETTE = {
    "light": {
        "ink": "#1F2328",
        "ink2": "#57606A",
        "ink3": "#8C959F",
        "rule": "#DDE0E3",
        "grid": "#EFEFF0",
        "signal": "#A31D1D",
        "fade": "#C9CDD1",
        "plot": "#6E7781",
    },
}

TOOLTIP = (
    "Live detection runs M1 (XGBoost) on the testbed split and stores alerts with their SHAP features in "
    "`live/alerts.db`. The numbers come from `results/`, written by `python -m eval.summarise`. "
    "Nothing in the dashboard recomputes a metric."
)


# --------------------------------------------------------------------------- theme


def setup() -> None:
    """Page config plus the stylesheet."""
    st.set_page_config(page_title="leakmate", layout="wide", initial_sidebar_state="expanded")
    st.markdown(f"<style>{(HERE / 'styles.css').read_text()}</style>", unsafe_allow_html=True)


def pal() -> dict[str, str]:
    return PALETTE["light"]


def chart_config() -> dict:
    """Just the plot config, for a chart that sets its own height."""
    return {"background": "transparent", "config": chart()["config"]}


def chart(height: int = 240) -> dict:
    """Altair `properties`: hairline axes, quiet labels, no chart border, page-coloured background."""
    p = pal()
    return {
        "height": height,
        "background": "transparent",
        "config": {
            "axis": {
                "labelColor": p["ink2"],
                "titleColor": p["ink2"],
                "titleFontSize": 11,
                "titleFontWeight": 600,
                "domainColor": p["rule"],
                "gridColor": p["grid"],
                "tickColor": p["rule"],
                "labelFontSize": 11,
            },
            "legend": {
                "labelColor": p["ink2"],
                "titleColor": p["ink2"],
                "labelFontSize": 11,
                # default right orientation: Vega-Lite reserves a column for it. A top or corner legend is
                # drawn inside the plot group and floats over the marks.
            },
            "view": {"stroke": "transparent"},
        },
    }


# --------------------------------------------------------------------------- navigation


def nav(pages: list[str], key: str = "page") -> str:
    """Brand and the view switch. The selected page is drawn as a filled box (styles.css)."""
    with st.sidebar:
        st.markdown('<div class="lm-brand">leakmate</div>', unsafe_allow_html=True)
        return st.radio("View", pages, key=key, label_visibility="collapsed", help=TOOLTIP, width="stretch")


# --------------------------------------------------------------------------- blocks


def masthead(eyebrow: str, title: str, sub: str) -> None:
    st.markdown(
        f'<div class="lm-head"><div class="lm-eyebrow">{eyebrow}</div>'
        f'<h1 class="lm-title">{title}</h1><p class="lm-sub">{sub}</p></div>',
        unsafe_allow_html=True,
    )


def strip(cells: list[tuple[str, str, bool]]) -> None:
    """Key figures: (label, value, is_hot). Wraps instead of clipping, so it holds down to 360 px."""
    items = "".join(
        f'<dl class="lm-cell{" lm-hot" if hot else ""}"><dt>{k}</dt><dd>{v}</dd></dl>' for k, v, hot in cells
    )
    st.markdown(f'<div class="lm-strip">{items}</div>', unsafe_allow_html=True)


def section(label: str, note: str = "") -> None:
    st.markdown(
        f'<div class="lm-sec">{label}</div>' + (f'<p class="lm-note">{note}</p>' if note else ""),
        unsafe_allow_html=True,
    )


def need(title: str, body_md: str) -> None:
    """The one honest empty state: what is missing, and the command that fills it."""
    st.warning(title)
    st.markdown(body_md)


def table(
    frame: pd.DataFrame, columns: list[tuple[str, str, str]], picked: str | None = None, max_rows: int = 250
) -> None:
    """An HTML table: ours, so it themes with the page and never reflows into a scrollbar.

    `columns` is a list of (key, label, kind) where kind is text, num, wire or mark. `picked` is a value of
    the first column that gets the highlight row.
    """
    if frame.empty:
        return
    rows = frame.head(max_rows)
    head = "".join(f'<th class="{"num" if kind == "num" else ""}">{label}</th>' for _, label, kind in columns)
    body = []
    for _, row in rows.iterrows():
        cls = ' class="is-picked"' if picked is not None and str(row[columns[0][0]]) == str(picked) else ""
        cells = "".join(f'<td class="{kind}">{_cell(row.get(key), kind)}</td>' for key, _, kind in columns)
        body.append(f"<tr{cls}>{cells}</tr>")
    st.markdown(
        f'<div class="lm-table-wrap"><table class="lm-table"><thead><tr>{head}</tr></thead>'
        f"<tbody>{''.join(body)}</tbody></table></div>",
        unsafe_allow_html=True,
    )


def _cell(value, kind: str) -> str:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return "&ndash;"
    if isinstance(value, (int,)) and not isinstance(value, bool):
        return f"{value:,}"
    if kind == "num" and isinstance(value, float):
        return f"{value:,.4f}"
    text = html.escape(str(value))  # cells hold query names and host addresses: data, never markup
    if kind == "mark":
        return f'<span class="mark">{text}</span>' if text else ""
    return text
