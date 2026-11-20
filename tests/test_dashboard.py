"""Dashboard renders from both sources, and never invents a number.

Runs the real `dashboard/app.py` with Streamlit's headless AppTest: no browser, no port. Fixtures use
`dashboard.demo`, the synthetic alerts.db, and the results CSVs already committed on main.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import pandas as pd
import pytest

# CI's m1 test group installs streamlit on top of requirements-m1, so these tests run there; the m2 group and
# any machine without streamlit skip the file. Locally: pip install -r requirements.txt
streamlit = pytest.importorskip("streamlit", reason="the dashboard needs streamlit (requirements.txt)")
from streamlit.testing.v1 import AppTest  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _own_the_environment():
    """`_app` writes process environment, and AppTest reads it at import time: without this, whichever test
    ran last decides which `alerts.db` the next one sees.
    """
    saved = dict(os.environ)
    yield
    os.environ.clear()
    os.environ.update(saved)


def _app(**env) -> AppTest:
    for key, value in env.items():
        os.environ[key] = value
    at = AppTest.from_file(str(ROOT / "dashboard" / "app.py"), default_timeout=90)
    at.run()
    return at


@pytest.fixture
def demo_db(tmp_path: Path) -> Path:
    from dashboard import demo

    out = tmp_path / "alerts.db"
    demo.build(out, minutes=5, seed=7)
    return out


def _has_table(at: AppTest) -> bool:
    """The tables are our own HTML, so they theme with the page instead of staying a white card."""
    return any('class="lm-table"' in str(m.value) for m in at.markdown)


def _page(at: AppTest, name: str) -> AppTest:
    at.sidebar.radio[0].set_value(name).run()
    return at


def test_overview_summarises_both_halves(demo_db: Path) -> None:
    at = _app(LEAKMATE_ALERTS_DB=str(demo_db))
    assert not at.exception, at.exception
    text = " ".join(str(w.value) for w in at.markdown)
    assert "Overview" in text and "Detector" in text and "Evaluation" in text
    assert "queries scored" in text and "median latency" in text  # live side reached the strip
    assert _has_table(at), "the per-experiment selection table is missing"
    assert len(at.get("vega_lite_chart")) == 3  # alerts over time, top hosts, latency bars
    assert at.button, "no way through to the detail pages"


def test_live_page_renders_from_a_database(demo_db: Path) -> None:
    at = _page(_app(LEAKMATE_ALERTS_DB=str(demo_db)), "Live")
    assert not at.exception, at.exception
    text = " ".join(str(w.value) for w in at.markdown)
    assert len(at.get("tabs")) == 4  # feed, score over time, why it fired, latency
    assert "queries scored" in text and "median latency" in text  # the batches table reached the strip
    assert at.get("dataframe"), "the alert feed is empty"
    # score over time and the latency histogram. The SHAP bars are not among them: nothing is explained
    # until a feed row is clicked.
    assert len(at.get("vega_lite_chart")) == 2


def test_results_page_renders_from_the_committed_results() -> None:
    at = _page(_app(LEAKMATE_ALERTS_DB=""), "Results")
    assert not at.exception, at.exception
    assert len(at.get("tabs")) == 5  # comparison, curves, latency, per tool, split order
    assert _has_table(at), "the comparison table is empty"
    assert len(at.get("vega_lite_chart")) == 4  # trade-off, latency, per-tool, split gap
    # the ROC curve and one confusion matrix. The wordmark is deliberately not counted: it is an inline
    # <img> in the navbar, not an st.image, so it carries no hover toolbar and no lightbox.
    assert len(at.get("image")) == 2
    labels = [str(o) for o in at.selectbox[0].options]
    assert any("Experiment 1" in label for label in labels)


def test_results_page_renders_from_the_runs_with_the_domain_hidden(monkeypatch) -> None:
    """results_nozone/ has no shuffled runs and no figures; the page says so and does not crash."""
    if not (ROOT / "results_nozone" / "summary.csv").exists():
        pytest.skip("results_nozone/summary.csv is not in this checkout")
    monkeypatch.setenv("LEAKMATE_RESULTS", str(ROOT / "results_nozone"))
    at = _page(_app(LEAKMATE_ALERTS_DB=""), "Results")
    assert not at.exception, at.exception
    assert _has_table(at), "the comparison table is empty"
    assert any("no shuffled runs" in str(c.value) for c in at.caption)


def test_missing_database_names_the_command_that_fills_it(tmp_path: Path) -> None:
    at = _page(_app(LEAKMATE_ALERTS_DB=str(tmp_path / "nothing.db")), "Live")
    assert not at.exception, at.exception
    body = " ".join(str(w.value) for w in at.markdown) + " ".join(str(w.value) for w in at.warning)
    assert "python -m live" in body
    assert "dashboard.demo" in body


def test_every_m1_feature_has_plain_words() -> None:
    from dashboard import explain

    assert set(explain.FEATURE_DOC) >= {
        "q_len",
        "sub_len",
        "longest_label",
        "n_labels",
        "entropy",
        "sub_entropy",
        "n_digits",
        "n_upper",
        "n_special",
        "digit_ratio",
        "qtype_code",
        "is_txt_null",
        "resp_size",
        "qlen_wire",
        "h_qpm",
        "h_uniq_ratio",
        "h_ent_mean",
        "h_ent_std",
        "h_len_mean",
        "h_parent_uniq",
        "h_txt_null_ratio",
    }
    for feature, (_, _, unit) in explain.FEATURE_DOC.items():
        line = explain.sentence(feature, 12.5, 0.4)
        assert line and "pushes" in line
        assert explain.value_text(feature, 12.5).startswith(("12", "yes", "no", "13")), feature
        if unit and unit not in ("flag", "ratio"):  # a ratio is printed as a bare number
            assert unit in line, feature
    assert explain.value_text("h_uniq_ratio", 1.0) == "1.00"
    assert explain.headline([{"feature": "h_uniq_ratio", "value": 1.0, "shap": 4.9}]) == "unique-name ratio 1.00"
    assert explain.headline([]) == "no explanation"
    assert "pushes toward tunnel" in explain.sentence("q_len", 118.0, 2.31)
    assert "away" in explain.sentence("h_qpm", 12.0, -0.2)


def test_latency_panel_survives_a_pre_batches_database(tmp_path: Path) -> None:
    """A database whose live.store predates `batches`: the page must say so, not crash."""
    import sqlite3

    path = tmp_path / "old.db"
    with sqlite3.connect(path) as db:
        db.executescript(
            "CREATE TABLE alerts (id INTEGER PRIMARY KEY, ts REAL, src_host TEXT, qname TEXT, qtype TEXT,"
            " score REAL, threshold REAL, model TEXT, top_features TEXT, detected_ts REAL);"
            "CREATE TABLE host_stats (bucket_ts REAL, src_host TEXT, queries INTEGER, alerts INTEGER,"
            " max_score REAL, sum_score REAL, PRIMARY KEY (bucket_ts, src_host));"
            "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);"
            "INSERT INTO meta VALUES ('model','m1_xgb'),('threshold','0.5'),('mode','replay');"
            "INSERT INTO host_stats VALUES (1.0, '172.28.0.10', 3, 0, 0.1, 0.3);"
        )
    at = _page(_app(LEAKMATE_ALERTS_DB=str(path)), "Live")
    assert not at.exception, at.exception
    assert any("batches" in str(c.value) for c in at.caption)


def test_demo_database_is_on_one_clock(demo_db: Path) -> None:
    """live.store stamps detected_ts and scored_ts with the wall clock; the demo must put both on its own
    clock, or the page sees a file spanning years and its window holds nothing."""
    from dashboard import data

    conn = data.connect(demo_db)
    alerts, batches, stats = data.read_alerts(conn), data.read_batches(conn), data.read_host_stats(conn)
    conn.close()
    first, last = stats["bucket_ts"].min(), stats["bucket_ts"].max()
    assert last - first < 5 * 60  # the five minutes the fixture asked for
    assert batches["scored_ts"].between(first, last + 30).all() and len(batches) == stats["bucket_ts"].nunique()
    assert (batches["first_ts"] < batches["last_ts"]).all() and (batches["last_ts"] <= batches["scored_ts"]).all()
    wait = alerts["detected_ts"] - alerts["ts"]
    assert wait.between(0.2, 1.6).all()  # the time to alert the generator drew, not today minus 2023


def test_query_names_are_escaped_before_they_reach_the_page(tmp_path: Path) -> None:
    """A DNS name is whatever the client sent. It is shown as text, never read as markup."""
    import sqlite3

    from dashboard import demo

    path = tmp_path / "alerts.db"
    demo.build(path, minutes=1, seed=3)
    evil = "<img src=x onerror=alert(1)>.evil.tunnel.test"
    with sqlite3.connect(path) as db:
        db.execute("UPDATE alerts SET qname = ? WHERE id = (SELECT MAX(id) FROM alerts)", (evil,))
        db.commit()
    escaped = "&lt;img src=x onerror=alert(1)&gt;.evil.tunnel.test"
    for page in ("Overview", "Live"):
        at = (
            _app(LEAKMATE_ALERTS_DB=str(path))
            if page == "Overview"
            else _page(_app(LEAKMATE_ALERTS_DB=str(path)), page)
        )
        assert not at.exception, at.exception
        body = " ".join(str(m.value) for m in at.markdown)
        # the navbar wordmark is the only <img> the page owns, and it is a local data URI; what must never
        # appear unescaped is markup that came off the wire
        assert not re.search(r"<img[^>]*onerror", body, re.I), page
        if page == "Overview":
            assert escaped in body, page  # the overview writes the newest alerts into HTML itself
        else:
            assert evil in _feed_names(at), page  # the grid receives the name as data, not as markup
            _click_row(at, _feed_names(at).index(evil))
            detail = " ".join(str(m.value) for m in at.markdown)
            assert escaped in detail, page  # the detail panel writes HTML, so there it must be escaped
            assert not re.search(r"<img[^>]*onerror", detail, re.I), page


def test_overview_shows_the_false_positive_rate_of_each_pick(demo_db: Path) -> None:
    at = _app(LEAKMATE_ALERTS_DB=str(demo_db))
    picks = next(str(m.value) for m in at.markdown if 'class="lm-table"' in str(m.value))
    assert ">FPR<" in picks and "&ndash;" not in picks  # every pick has a rate
    assert any("results_nozone" in str(c.value) for c in at.caption)  # and says which selection to quote


def test_time_axes_are_in_utc(demo_db: Path) -> None:
    """The feed and the captions give UTC; a chart axis in the browser's zone would disagree with them."""
    import json

    for page in ("Overview", "Live"):
        at = (
            _app(LEAKMATE_ALERTS_DB=str(demo_db))
            if page == "Overview"
            else _page(_app(LEAKMATE_ALERTS_DB=str(demo_db)), page)
        )
        specs = [json.dumps(json.loads(c.proto.spec)) for c in at.get("vega_lite_chart")]
        timed = [s for s in specs if '"type": "temporal"' in s]
        assert timed, page
        assert all('"scale": {"type": "utc"}' in s for s in timed), page


def test_data_loaders_read_the_documented_shape(demo_db: Path) -> None:
    from dashboard import data

    conn = data.connect(demo_db)
    assert conn is not None
    meta = data.read_meta(conn)
    assert meta["mode"] in {"sniff", "replay"} and meta["model"] == "m1_xgb"
    alerts = data.read_alerts(conn)
    assert {"ts", "src_host", "qname", "score", "top_features", "detected_ts"} <= set(alerts.columns)
    assert alerts["features"].map(lambda f: isinstance(f, list)).all()
    batches = data.read_batches(conn)
    assert not batches.empty
    assert "ms_per_query" not in batches.columns  # the panel derives it, the file does not carry it
    stats = data.read_host_stats(conn)
    assert isinstance(stats, pd.DataFrame) and not stats.empty
    conn.close()


def test_read_alerts_keeps_the_newest_rows(demo_db: Path) -> None:
    """The cap must trim the old end: the file only ever grows at the top, and trimming the bottom made
    every recent window look like an empty past."""
    from dashboard import data

    conn = data.connect(demo_db)
    whole = data.read_alerts(conn)
    capped = data.read_alerts(conn, limit=50)
    assert capped["ts"].max() == whole["ts"].max()
    assert capped["ts"].min() > whole["ts"].min()
    assert len(capped) == 50
    conn.close()


def test_window_slider_filters_every_panel(demo_db: Path) -> None:
    """The window used to reach one chart only, so sliding it appeared to do nothing."""
    at = _page(_app(LEAKMATE_ALERTS_DB=str(demo_db)), "Live")
    wide = _strip_value(at, "queries scored")
    at.slider[0].set_value(1).run()
    assert not at.exception, at.exception
    narrow = _strip_value(at, "queries scored")
    assert wide is not None and narrow is not None
    assert int(narrow.replace(",", "")) < int(wide.replace(",", ""))
    assert any("Last 1 min" in str(c.value) for c in at.caption)


def _strip_value(at: AppTest, label: str) -> str | None:
    import re

    for m in at.markdown:
        v = str(m.value)
        if 'class="lm-strip"' in v:
            found = re.search(rf"<dt>{label}</dt><dd>([\d,.]+)", v)
            return found.group(1) if found else None
    return None


def test_results_directory_can_be_pointed_elsewhere(tmp_path: Path, monkeypatch) -> None:
    from dashboard import data

    monkeypatch.setenv(data.RESULTS_ENV, str(tmp_path))
    assert data.results_dir() == tmp_path
    assert data.read_table("summary").empty  # missing file is an empty frame, not an error
    assert data.figure("roc", experiment="E1") is None


def _feed_frame(at):
    """The rows the feed is showing. It is a real grid, because a row has to be clickable."""
    return at.get("dataframe")[0].value


def _feed_rows(at) -> int:
    return len(_feed_frame(at))


def _feed_names(at) -> list[str]:
    return list(_feed_frame(at)["query name"])


def _feed_scores(at) -> list[float]:
    return [float(x) for x in _feed_frame(at)["score"]]


def _click_row(at, index: int) -> None:
    """Select a feed row the way the grid reports it, and run."""
    at.session_state["lm_feed_grid_1_50"] = {"selection": {"rows": [index], "columns": [], "cells": []}}
    at.run()


def test_feed_pages_through_every_alert_it_matches(demo_db: Path) -> None:
    at = _page(_app(LEAKMATE_ALERTS_DB=str(demo_db)), "Live")
    caption = next(str(m.value) for m in at.caption if "alerts" in str(m.value))
    total = int(re.search(r"of ([\d,]+) alerts", caption)[1].replace(",", ""))
    assert total > 250, "the demo database should be big enough to need pages"
    assert _feed_rows(at) == 50, "default page size"

    at.sidebar.radio[0].set_value("Live")  # stay on the page: the widgets below belong to the feed tab
    at.session_state["lm_feed_rows"] = 25
    at.run()
    assert _feed_rows(at) == 25
    page1 = _feed_names(at)

    at.session_state["lm_feed_page"] = 2
    at.run()
    page2 = _feed_names(at)
    assert page2 and not set(page2) & set(page1), "page 2 repeated page 1"
    assert "Rows 26-50" in next(str(m.value) for m in at.caption if "alerts" in str(m.value))

    at.session_state["lm_feed_search"] = ".tunnel.test"
    at.run()
    narrow = int(
        re.search(r"of ([\d,]+) alerts", next(str(m.value) for m in at.caption if "alerts" in str(m.value)))[1].replace(
            ",", ""
        )
    )
    assert 0 < narrow <= total


def test_feed_sort_changes_what_the_first_page_holds(demo_db: Path) -> None:
    at = _page(_app(LEAKMATE_ALERTS_DB=str(demo_db)), "Live")

    def scores(at) -> list[float]:
        return _feed_scores(at)

    at.session_state["lm_feed_sort"] = "Highest score"
    at.run()
    top = scores(at)
    assert top and top == sorted(top, reverse=True), top[:4]
    at.session_state["lm_feed_sort"] = "Lowest score"
    at.run()
    low = scores(at)
    assert low and low == sorted(low) and low[0] <= top[-1], low[:4]


def _page_text(at) -> str:
    return " ".join(str(m.value) for m in at.markdown)


def test_no_alert_is_explained_until_one_is_clicked(demo_db: Path) -> None:
    at = _page(_app(LEAKMATE_ALERTS_DB=str(demo_db)), "Live")
    assert "Click a row in the feed" in _page_text(at)
    assert not st_shap_chart(at), "an alert was explained with nothing selected"


def test_clicking_a_feed_row_opens_that_alert(demo_db: Path) -> None:
    at = _page(_app(LEAKMATE_ALERTS_DB=str(demo_db)), "Live")
    import sqlite3

    from dashboard import data

    with sqlite3.connect(demo_db) as conn:
        conn.row_factory = sqlite3.Row
        alert_id = int(data.alert_page(conn, limit=50)[0]["id"].iloc[2])  # the third row of the first page
    _click_row(at, 2)
    assert at.session_state["lm_alert"] == alert_id
    assert f"alert {alert_id:,}" in _page_text(at)
    # the point of the click: the section changed too, and nothing reloaded
    assert at.session_state["live_section"] == "Alert trigger"
    assert st_shap_chart(at), "the SHAP contributions were not drawn"


def test_clearing_the_alert_returns_to_the_prompt(demo_db: Path) -> None:
    at = _page(_app(LEAKMATE_ALERTS_DB=str(demo_db)), "Live")
    _click_row(at, 0)
    assert "Click a row in the feed" not in _page_text(at)
    next(b for b in at.button if b.label == "Clear").set_value(True).run()
    assert "lm_alert" not in at.session_state
    assert at.session_state["live_section"] == "Alert feed"
    assert "Click a row in the feed" in _page_text(at)


def st_shap_chart(at) -> bool:
    """Any altair chart whose encoding is the SHAP contribution axis."""
    return any("SHAP contribution" in str(c.spec) for c in at.get("vega_lite_chart"))


def test_the_navbar_still_works_after_opening_an_alert(demo_db: Path) -> None:
    """The click routes to Live once. On every run it would pin the page and the section."""
    at = _page(_app(LEAKMATE_ALERTS_DB=str(demo_db)), "Live")
    _click_row(at, 1)
    assert at.sidebar.radio[0].value == "Live"
    at.sidebar.radio[0].set_value("Overview").run()
    assert at.sidebar.radio[0].value == "Overview", "the navbar is pinned to Live"
    assert not at.exception, at.exception


def test_the_sections_are_nouns(demo_db: Path) -> None:
    at = _page(_app(LEAKMATE_ALERTS_DB=str(demo_db)), "Live")
    labels = [str(t.label) for t in at.get("tabs")]
    assert labels == ["Alert feed", "Score over time", "Alert trigger", "Latency"], labels
