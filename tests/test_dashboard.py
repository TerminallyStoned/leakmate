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
    assert _has_table(at), "the alert feed is empty"
    assert len(at.get("vega_lite_chart")) == 3  # score over time, SHAP bars, latency histogram


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
        assert escaped in body, page


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
