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
PAGES[page].render()
