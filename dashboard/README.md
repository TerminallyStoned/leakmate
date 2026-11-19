# leakmate dashboard

Three pages, all read-only. **Overview** answers "is it working, and what did we find" on one screen;
**Live** is the detector detail (feed, score over time, why each alert fired, batch latency) and **Results**
is the evaluation detail (comparison, curves, latency, per tool, split order). Sidebar collapses to a rail and
expands again, and the selected page is marked with a filled box rather than a radio button. Nothing recomputes a
metric: the numbers come from
`results/*.csv` (`python -m eval.summarise`) and the alerts from `live/alerts.db` (`python -m live`), so the
dashboard cannot disagree with them. Trello: "[Neo] Streamlit dashboard: results page + live alerts page".

## Run it

```bash
pip install -r requirements.txt                       # streamlit is in here
streamlit run dashboard/app.py                        # results/ + live/alerts.db
```

No `live/alerts.db` yet (nobody has run the sniffer)? Write a synthetic one and point the app at it:

```bash
python -m dashboard.demo                              # -> /tmp/demo_alerts.db (invented data, layout only)
LEAKMATE_ALERTS_DB=/tmp/demo_alerts.db streamlit run dashboard/app.py
```

Other switches:

| Variable | Effect |
|---|---|
| `LEAKMATE_RESULTS=results_nozone` | the runs with the lab domain hidden, instead of `results/` |
| `LEAKMATE_ALERTS_DB=/tmp/demo_alerts.db` | read another SQLite file |
| `LEAKMATE_PAGE=Results` | open on that page; used to take the report screenshots one at a time |

## Live page

| Panel | Source | Notes |
|---|---|---|
| Status strip | `meta` + `host_stats` + `batches` | model, threshold, queries scored, alerts, alert rate, median ms/query, mode |
| Score over time | `host_stats` | mean score per host per 10 s bucket; red dots mark buckets containing an alert |
| Alert feed | `alerts` | newest first, with the strongest feature of each alert in words |
| Why this alert fired | `alerts.top_features` | SHAP contributions as bars, plus one sentence each (`dashboard/explain.py`) |
| Processing latency | `batches` | ms per query, median and 95th percentile, against the 10 ms rule |

`meta.mode` decides one reading: with `mode = replay` the source was a capture file, so packet times are not
wall-clock and **time to alert is not meaningful**; with `mode = sniff` it is (`detected_ts - ts`). The page
says which is which instead of showing a number that would be wrong.

The `batches` table and `meta.mode` arrive with PR #47. On an older database the latency panel says so and
points at `results/latency_cpu.csv`; every other panel is unaffected.

## Results page

Experiment selector, then: model comparison table (the model `results/selection.csv` picked is marked),
recall against false-positive rate with the 10 ms rule as the colour split, ROC and confusion-matrix figures,
the latency chart, the per-tool recall grid for Experiment 3, and the Experiment S shuffled-vs-time pair.
Host-averaged and ablation runs are behind one toggle so the six headline models stay readable.

## Files

| File | Role |
|---|---|
| `dashboard/app.py` | entry point and page switch |
| `dashboard/shell.py` | the palette, the navbar, status strips, the HTML tables |
| `dashboard/styles.css` | chrome: hairlines, one signal colour, tabular figures |
| `dashboard/data.py` | the only place that opens `results/` and `alerts.db` |
| `dashboard/view_live.py`, `dashboard/view_results.py` | the two pages |
| `dashboard/explain.py` | plain words for the M1 feature names SHAP reports |
| `dashboard/demo.py` | synthetic `alerts.db` for layout and screenshots, never for numbers |
| `.streamlit/config.toml` | Streamlit's theme, fixed when the server starts |

Tests: `python -m pytest tests/test_dashboard.py` (renders both pages headlessly with Streamlit's AppTest).
