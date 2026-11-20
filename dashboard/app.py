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

# A feed row is an anchor to `?lm_alert=<id>`, and an anchor is a page load: read the alert and route back to
# the page that shows it, otherwise the click lands on Overview and is lost. The parameter stays in the URL,
# which makes an explained alert linkable; Clear is what takes it out.
# Mutating query params from the script body asks for a rerun, so nothing is popped here.
_alert = st.query_params.get("lm_alert")
if _alert:
    try:
        st.session_state["lm_alert"] = int(_alert)
    except ValueError:  # anything can be in a URL, including garbage
        st.session_state.pop("lm_alert", None)
    else:
        st.session_state["page"] = "Live"

page = shell.nav(list(PAGES), key="page")
PAGES[page].render()
