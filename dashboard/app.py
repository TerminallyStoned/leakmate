"""leakmate dashboard: an overview of the detector and the frozen results, with a detailed tab page each.

    streamlit run dashboard/app.py                       # results/ and live/alerts.db
    LEAKMATE_RESULTS=results_nozone streamlit run dashboard/app.py   # the lab-domain-hidden runs
    LEAKMATE_ALERTS_DB=/tmp/demo_alerts.db streamlit run dashboard/app.py   # a demo database

Overview summarises both halves of the project on one screen; Live and Results are the detailed views the
The pages: a summary of both halves of the project, the live detector's detail, and the frozen comparison.
Nothing here recomputes a metric.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:  # `streamlit run` puts dashboard/ on the path, not the repo root
    sys.path.insert(0, str(ROOT))

from dashboard import shell, view_live, view_overview, view_results  # noqa: E402

shell.setup()

PAGES = {"Overview": view_overview, "Live": view_live, "Results": view_results}
DEFAULT = os.environ.get("LEAKMATE_PAGE", "Overview")
if DEFAULT not in PAGES:
    shell.need(f"LEAKMATE_PAGE={DEFAULT!r} is not a page", "Use one of Overview, Live, Results.")
    st.stop()
if st.session_state.get("page") not in PAGES:
    st.session_state["page"] = DEFAULT

page = shell.nav(list(PAGES), key="page")

# Entering a page starts at its first section. Without this, the section bound to the tab strip survives a trip
# to Results and back, so Live reopens on whatever alert was last open. A row press is the exception: its
# callback runs before this and asks for the trigger section by setting the marker.
if not st.session_state.pop("lm_opened_alert", False) and st.session_state.get("lm_last_page") != page:
    st.session_state["live_section"] = "Alert feed"
st.session_state["lm_last_page"] = page

# Overview and Live read live/alerts.db, which the sniffer keeps writing: re-run just the page body on a timer
# (a fragment), so new alerts appear without a reload and the navbar, filters and open alert stay as they are.
# Results is frozen and is drawn once. LEAKMATE_REFRESH_S=0 turns the timer off.
try:
    REFRESH_S = float(os.environ.get("LEAKMATE_REFRESH_S", "5"))
except ValueError:
    shell.need("LEAKMATE_REFRESH_S is not a number", "Give seconds, for example 5, or 0 to turn the refresh off.")
    st.stop()
if page in ("Overview", "Live") and REFRESH_S > 0:
    st.fragment(run_every=REFRESH_S)(PAGES[page].render)()
else:
    PAGES[page].render()
