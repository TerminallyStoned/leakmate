"""Streamlit dashboard (planned, Phase 4, due 20 Nov).

    streamlit run dashboard/app.py

Planned pages: results (from `python -m eval.summarise` output in results/) and live alerts.
Until then it shows a notice so the command in the README works.
"""

import streamlit as st

st.set_page_config(page_title="leakmate", layout="wide")
st.title("leakmate dashboard")
st.info(
    "Not built yet. The results page and live alerts page land in Phase 4 (20 Nov). "
    "Until then, run `python -m eval.summarise` and open results/summary.csv and results/figures/."
)
