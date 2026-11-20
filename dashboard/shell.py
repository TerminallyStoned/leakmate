"""Page furniture shared by the three pages: theme, navigation, masthead, strips, tables.

One source of colour and type, so the pages read as one product. The dark purple theme is resolved by
Streamlit when the server starts (see .streamlit/config.toml) and cannot change at runtime, so the dashboard
owns one palette and the charts read it from here rather than from module constants.
"""

from __future__ import annotations

import base64
import functools
import html
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

HERE = Path(__file__).resolve().parent
LOGO = HERE / "assets" / "leakmate_logo.png"

#: x scale for every time axis. Vega draws times in the browser's zone unless told otherwise, and the feed,
#: the captions and live/README.md are all in UTC.
UTC = alt.Scale(type="utc")

#: chart colours, mirroring the OKLCH tokens in styles.css as sRGB (Vega needs concrete paint values)
PALETTE = {
    "ink": "#EDEBF6",
    "ink2": "#A9A4C0",
    "ink3": "#6F6A87",
    "rule": "rgba(255,255,255,0.20)",
    "grid": "rgba(255,255,255,0.06)",
    "signal": "#C4A6FF",
    "fade": "#4C4767",
    "plot": "#8B86A8",
    "alert": "#F0616B",
    "over": "#E3B163",
}

#: colour means model family, everywhere. Three hues at matched lightness plus a neutral for baselines,
#: so a chart can be read by family without a legend hunt. Values match --fam-* in styles.css.
FAMILIES = {
    "supervised": "oklch(74% 0.16 305)",
    "unsupervised": "oklch(76% 0.13 190)",
    "leakage": "oklch(80% 0.14 78)",
    "baseline": "oklch(70% 0.02 285)",
}
FAMILY_LABEL = {
    "supervised": "Supervised (M1)",
    "unsupervised": "Unsupervised (M2)",
    "leakage": "Leakage (M3)",
    "baseline": "Baseline",
}
FAMILY_OF = {
    "m1": "supervised",
    "m1_testbed": "supervised",
    "m2": "unsupervised",
    "m2_ablation1_char": "unsupervised",
    "m3_cnn": "leakage",
    "m3_bilstm": "leakage",
    "rf": "baseline",
    "iforest": "baseline",
}


def family(model: str) -> str:
    """The model family a row belongs to: exact name, then prefix, then baseline."""
    base = model.split("_hostavg")[0].split("_ablation")[0]
    if base in FAMILY_OF:
        return FAMILY_OF[base]
    if base.startswith("m1"):
        return "supervised"
    if base.startswith("m2"):
        return "unsupervised"
    if base.startswith("m3"):
        return "leakage"
    return "baseline"


TOOLTIP = (
    "Live detection runs M1 (XGBoost) on the testbed split and stores alerts with their SHAP features in "
    "`live/alerts.db`. The numbers come from `results/`, written by `python -m eval.summarise`. "
    "Nothing in the dashboard recomputes a metric."
)


# --------------------------------------------------------------------------- theme


def setup() -> None:
    """Page config plus the stylesheet."""
    icon = str(LOGO) if LOGO.exists() else None
    st.set_page_config(page_title="leakmate", page_icon=icon, layout="wide", initial_sidebar_state="expanded")
    st.markdown(f"<style>{(HERE / 'styles.css').read_text()}</style>", unsafe_allow_html=True)


def pal() -> dict[str, str]:
    """The one palette: the app is dark, and Vega needs sRGB rather than the CSS tokens."""
    return PALETTE


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
                "gridWidth": 1,
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


@functools.lru_cache(maxsize=1)
def logo_tag() -> str:
    """The wordmark as a data URI: an inline <img> is page furniture, with no toolbar and no lightbox."""
    if not LOGO.exists():
        return ""
    b64 = base64.b64encode(LOGO.read_bytes()).decode()
    return f'<img class="lm-logo" src="data:image/png;base64,{b64}" alt="leakmate" draggable="false">'


def nav(pages: list[str], key: str = "page") -> str:
    """Brand and the view switch. The selected page is drawn as a filled box (styles.css)."""
    with st.sidebar:
        brand = logo_tag()
        st.markdown(
            brand or '<div class="lm-brand">leakmate</div>',
            unsafe_allow_html=True,  # the asset is optional: the navbar still says what the app is
        )
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


# --------------------------------------------------------------------------- small icons


def icon(name: str, tone: str = "") -> str:
    """Inline SVG, 1.6 stroke - the weight of the body text it sits beside, per the icon rule."""
    paths = {
        "ok": '<path d="M20 6 9 17l-5-5"/>',
        "warn": '<path d="M12 9v4m0 4h.01M10.3 3.9 2.5 17.5A2 2 0 0 0 4.2 20.5h15.6a2 2 0 0 0 1.7-3L13.7 3.9"/>',
        "alert": '<circle cx="12" cy="12" r="9"/><path d="M12 8v4m0 4h.01"/>',
        "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
        "trend": '<path d="M3 17l6-6 4 4 7-7"/><path d="M14 8h6v6"/>',
    }
    cls = f' class="{tone}"' if tone else ""
    return (
        f'<svg{cls} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" '
        f'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{paths.get(name, paths["ok"])}</svg>'
    )


def key() -> None:
    """The family legend, once, where family colour is first used."""
    spans = "".join(
        f'<span><i class="lm-dot" style="background:{FAMILIES[f]}"></i>{FAMILY_LABEL[f]}</span>' for f in FAMILIES
    )
    st.markdown(f'<div class="lm-key">{spans}</div>', unsafe_allow_html=True)


def verdicts(rows: list[tuple[str, str, str]]) -> None:
    """Conclusions as statements: (icon, html body, tone class)."""
    items = "".join(f'<div class="lm-verdict {tone}">{icon(name)}<p>{body}</p></div>' for name, body, tone in rows)
    st.markdown(f'<div class="lm-verdicts">{items}</div>', unsafe_allow_html=True)
