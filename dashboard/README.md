# leakmate dashboard

Three pages, all read-only, on a dark purple chrome: colour is authored in OKLCH, borders are alpha, depth
comes from lighter surfaces rather than shadows, and every categorical colour in a chart means model family. **Overview** answers "is it working, and what did we find" on one screen;
**Live** is the detector detail (feed, score over time, why each alert fired, batch latency) and **Results**
is the evaluation detail (comparison, curves, latency, per tool, split order). Sidebar collapses to a rail and
expands again, and the selected page is marked with a filled box rather than a radio button. Nothing recomputes a
metric: the numbers come from
`results/*.csv` (`python -m eval.summarise`) and the alerts from `live/alerts.db` (`python -m live`), so the
dashboard cannot disagree with them.

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
| `LEAKMATE_REFRESH_S=10` | how often Overview and Live re-read `alerts.db` (default 5 s; `0` turns it off) |

## Chrome

Dark purple by default: `.streamlit/config.toml` resolves the theme when the server starts, which is the only
moment Streamlit reads it. The bar itself (in `styles.css`) authors colour in OKLCH, uses alpha borders so
they blend into whichever surface they sit on, and shows depth with lighter surfaces instead of shadows.
The navbar hugs the wordmark's width and is not draggable; the override is scoped to
`:not([data-collapsed="true"])` so Streamlit's own collapse still takes over when the bar is closed. It opens
on load (`initial_sidebar_state="expanded"`); a browser that was closed by hand remembers that in
`localStorage` and reopens closed, which is the user's own last choice rather than the app's.

The wordmark is an inline `<img>` with a data URI, not `st.image`, so it has no hover toolbar and no
click-to-fullscreen: it is page furniture. `dashboard/assets/leakmate_logo.png` is derived from the provided
artwork by keying the black background out with a flood fill from the frame, which is what keeps the black
letters inside the orange chip opaque.

## Opening an alert

Every row of the feed is one full-width button: the whole row is the control, there is no checkbox column and
no link. `view_live._open_alert` is the button's callback, and because a callback runs before the app renders,
the press sets the alert **and** selects the **Alert trigger** section in the same step, with no page load. The
strip is bound to the URL (`st.tabs(..., bind="query-params")`), which is also the only way a tab can be moved
programmatically: writing `live_section` through `st.query_params` raises, and writing it after the strip
exists does nothing.

Row labels are padded to fixed field widths by `view_live._columns`, which the column header uses too, so one
string is both the label and the header. For that to hold, four things have to be true at once, and `qa_visual.py`
measures the result at every width rather than trusting them:

- the label text is monospace **all the way down**. Streamlit sets its own `font-family` on the paragraph inside
  a button label, and an inherited font on the wrapper loses to it, so every node holding label text is pinned
  to `--mono`;
- `--mono` starts with a real monospace face. `ui-monospace` looks correct in devtools but renders `U+00A0`
  narrower than a digit in Chromium on Linux, and padding is `U+00A0`;
- no `letter-spacing` and the same `font-weight` on header and rows. A wider face, or tracking, moves every
  column by a fraction of a character each, so the error grows along the row;
- the header is a button label, not HTML. Rendered through `st.markdown` it goes down a different text path and
  the padding comes out at a different width.

Long query names truncate at the end, where the label is least informative.

Nothing is explained until a row is pressed. The alert is then read by primary key, so any alert in the file can
be explained, not only the ones a panel happens to hold. `Clear` forgets it and returns to the feed.

## Live page

Overview and Live re-run every `LEAKMATE_REFRESH_S` seconds as a fragment (`dashboard/app.py`), so alerts
appear while the sniffer writes without a reload; the navbar, filters, window and open alert keep their state.
Results is frozen and is drawn once.

| Panel | Source | Notes |
|---|---|---|
| Status strip | `meta` + `host_stats` + `batches` | model, threshold, queries scored, alerts, alert rate, median ms/query, mode. The alert counters are `COUNT(*)` over the window, not a count of the loaded rows |
| Score over time | `host_stats` | mean score per host per 10 s bucket; red dots mark buckets containing an alert |
| Alert feed | `alerts` | filter (name contains, minimum score), sort, page. SQLite does all three, so the page is a slice and the count is the whole set. Each row is a button that opens that alert |
| Alert trigger | `alerts` by id | nothing until a row is clicked, then the score, the threshold, time to alert, the SHAP bars and one sentence per feature |
| Processing latency | `batches` | ms per query, median and 95th percentile, against the 10 ms rule |

`meta.mode` decides one reading: with `mode = replay` the source was a capture file, so packet times are not
wall-clock and **time to alert is not meaningful**; with `mode = sniff` it is (`detected_ts - ts`). The page
says which is which instead of showing a number that would be wrong.

The `batches` table and `meta.mode` were added on 19 Nov. On an older database the latency panel says so and
points at `results/latency_cpu.csv`; every other panel is unaffected.

Paging is offered twice, because a fifty row page puts the controls at the top out of reach: the number input
above the table is labelled with the running total (`Page 3/97`), and a strip below the table carries
**Previous**, the position (`3 / 97`), and **Next**. The two buttons are filled - the accent hue, the rim and the
glow every other raised surface here uses - and they sit on the table's own left and right edges with the position
centred between them, so the strip reads as belonging to the rows it moves. At the first page `Previous` and at
the last page `Next` lose the accent, the rim and the light and go flat grey in place, rather than wrapping to the
other end: a control that jumps somewhere unexpected is worse than one that does nothing. Pressing either writes
the paging widget's key from a callback, which is what lets one press both move the page and re-render the slice.

Query names, host addresses and anything else read from `alerts.db` are escaped before they go into the page:
a DNS name is whatever the client sent, and the tables and alert panels are the dashboard's own HTML.

## Results page

**Which selection to quote.** `results/` holds the original testbed names, where every tunnel name ends in
`tunnel.test`; a model that reads names scores perfectly there from the suffix. The Overview therefore quotes
Experiments 1, 3 and 5 from `results_nozone/` (the runs with the domain hidden, `data.read_selection`) and 2 and 4
from `results/`. The Results page shows whichever set `LEAKMATE_RESULTS` names and says which (`docs/suffix-ablation.md`).

Experiment selector, then: model comparison table (the model `selection.csv` picked is marked),
recall against false-positive rate with the 10 ms rule as the colour split, ROC and confusion-matrix figures,
the latency chart, the per-tool recall grid for Experiment 3, and the Experiment S shuffled-vs-time pair.
Host-averaged and ablation runs are behind one toggle so the six headline models stay readable.

## Files

| File | Role |
|---|---|
| `dashboard/app.py` | entry point and page switch |
| `dashboard/shell.py` | the palette, the navbar, status strips, the HTML tables |
| `dashboard/styles.css` | chrome: OKLCH tokens, alpha hairlines, one accent, tabular figures |
| `dashboard/assets/leakmate_logo.png` | the wordmark, background keyed out so it sits on the dark surface |
| `dashboard/data.py` | the only place that opens `results/` and `alerts.db` |
| `dashboard/view_live.py`, `dashboard/view_results.py` | the two pages |
| `dashboard/explain.py` | plain words for the M1 feature names SHAP reports |
| `dashboard/demo.py` | synthetic `alerts.db` for layout and screenshots, never for numbers |
| `.streamlit/config.toml` | the dark purple theme, resolved by Streamlit when the server starts |

Tests: `python -m pytest tests/test_dashboard.py` (renders the pages headlessly with Streamlit's AppTest; CI
runs them in its m1 group).
