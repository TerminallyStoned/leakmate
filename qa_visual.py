"""Browser sweep for the dashboard: every page, every section, three widths, with real clicks.

A dev tool, not a deliverable: `python qa_visual.py`, against the app on :8501. It checks the things a
screenshot review misses: horizontal overflow, console errors, elements wider than their container, and
controls that stop responding after the state has moved.
"""

from __future__ import annotations

import sys

from playwright.sync_api import sync_playwright

URL = "http://127.0.0.1:8501/"
WIDTHS = (1440, 834, 390)
PAGES = ("Overview", "Live", "Results")
FAILURES: list[str] = []
PASSED = 0

METRICS = """() => {
  const vw = document.documentElement.clientWidth;
  const main = document.querySelector('[data-testid="stMain"]');
  const wide = [];
  document.querySelectorAll('body *').forEach((e) => {
    const r = e.getBoundingClientRect();
    if (r.width > vw + 2 && getComputedStyle(e).position !== 'fixed') {
      wide.push(e.getAttribute('data-testid') || e.tagName);
    }
  });
  const clipped = [];
  document.querySelectorAll('.st-key-lm_feed_head [data-testid^="stBaseButton-"], .lm-table, .lm-note').forEach((e) => {
    const ox = getComputedStyle(e).overflowX;
    // a box that scrolls is not a box that hides content
    if (e.scrollWidth > e.clientWidth + 2 && ox !== 'auto' && ox !== 'scroll') {
      clipped.push(String(e.className).split(' ')[0]);
    }
  });
  return {
    overflow: document.documentElement.scrollWidth - vw,
    widest: wide.slice(0, 3),
    clipped: clipped.slice(0, 3),
    mainHeight: main ? Math.round(main.getBoundingClientRect().height) : 0
  };
}"""

PROSE = """() => {
  const capped = [];
  document.querySelectorAll('.lm-note, .lm-head p').forEach((e) => {
    const cs = getComputedStyle(e);
    const rect = e.getBoundingClientRect();
    if (cs.maxWidth !== 'none') {
      capped.push('max-width:' + cs.maxWidth);
    }
    // only a visible paragraph with real length: tab bodies that are not open measure zero
    const parent = e.parentElement.getBoundingClientRect().width;
    if (rect.width > 0 && parent > 0 && e.textContent.trim().length > 120 && rect.width < parent - 40) {
      capped.push(Math.round(rect.width) + '/' + Math.round(parent));
    }
  });
  return {capped: capped.slice(0, 3)};
}"""

FEED_ALIGN = """() => {
  const nodes = (root) => { const w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT); const a = []; let n;
    while ((n = w.nextNode())) if (n.nodeValue.length) a.push(n); return a; };
  const xAt = (root, abs) => { let acc = 0; for (const n of nodes(root)) {
      if (abs < acc + n.nodeValue.length) { const r = document.createRange(); r.setStart(n, abs - acc); r.setEnd(n, abs - acc + 1);
        return r.getBoundingClientRect().left; } acc += n.nodeValue.length; } return NaN; };
  const h = document.querySelector('.st-key-lm_feed_head [data-testid^="stBaseButton-"]');
  const row = [...document.querySelectorAll('.st-key-lm_feed_stack [data-testid^="stBaseButton-"]')].find((e) => !e.disabled);
  if (!h || !row) { return {error: 'head or row missing'}; }
  // the first row's own label is padded by the same helper, so the same character index is the same column
  const len = Math.min(h.textContent.length, row.textContent.length);
  const cols = [0, 11, 30, 37, Math.floor(len / 2), len - 1].filter((c) => c >= 0 && c < len);
  const drift = cols.map((c) => [c, Math.round((xAt(h, c) - xAt(row, c)) * 10) / 10]);
  return {drift: drift, worst: Math.max(...drift.map((d) => Math.abs(d[1])))};
}"""

PAGER = """() => {
  const q = document.querySelector('.st-key-lm_pager');
  if (!q) { return {error: 'no pager'}; }
  const on = (el) => el.getBoundingClientRect().width > 0;
  const btns = [...q.querySelectorAll('button')].filter(on);
  const plate = document.querySelector('.st-key-lm_feed_stack').getBoundingClientRect();
  const num = q.querySelector('.lm-pager-num');
  if (btns.length < 2 || !num) { return {error: 'pager incomplete', btns: btns.length}; }
  // the glyphs, not the block: the number sits in a full width element, so its box is centred even when the
  // text inside it is not
  const tn = [...num.childNodes].find((c) => c.nodeType === 3 && c.nodeValue.trim());
  const range = document.createRange();
  range.selectNodeContents(tn || num);
  const nr = range.getBoundingClientRect();
  return {
    leftGap: Math.round(Math.abs(btns[0].getBoundingClientRect().left - plate.left)),
    rightGap: Math.round(Math.abs(btns[1].getBoundingClientRect().right - plate.right)),
    centreGap: Math.round(Math.abs(nr.left + nr.width / 2 - (plate.left + plate.width / 2))),
    text: num.textContent.trim(),
    prevOff: btns[0].disabled,
    nextOff: btns[1].disabled,
    below: Math.round(btns[0].getBoundingClientRect().top - plate.bottom)
  };
}"""

SELECTED = (
    "() => [...document.querySelectorAll('[role=tab]')].find(t => t.getAttribute('aria-selected') === 'true').innerText"
)


def check(name: str, ok: bool, detail: str = "") -> None:
    global PASSED
    if ok:
        PASSED += 1
    else:
        FAILURES.append(f"{name} :: {detail}")
        print(f"FAIL {name} :: {detail}")


def soft_click(locator, label: str) -> bool:
    """Click whatever instance is reachable; a hidden duplicate of a panel is not a failure."""
    try:
        locator.last.click(force=True, timeout=12000)
        return True
    except Exception as exc:  # noqa: BLE001 - the sweep reports, it does not raise
        check(f"clickable: {label}", False, str(exc)[:90])
        return False


def watched_page(ctx):
    """A page plus the list its console errors land in.

    The list is created here so each page's handlers close over their own: built inside the width loop they
    would all share one variable and a stale page could append to the next one's errors.
    """
    pg = ctx.new_page()
    errors: list[str] = []

    def on_console(message) -> None:
        if message.type == "error":
            errors.append(message.text[:120])

    def on_pageerror(exc: BaseException) -> None:
        errors.append(str(exc)[:120])

    pg.on("console", on_console)
    pg.on("pageerror", on_pageerror)
    return pg, errors


def goto_page(pg, name: str) -> None:
    """Switch pages through the navbar, at any width.

    Below Streamlit's breakpoint the bar is collapsed and its options are off-canvas, so it is expanded first:
    clicking an element that cannot be seen is a harness bug, not a page bug.
    """
    collapsed = pg.evaluate(
        "() => document.querySelector('[data-testid=\"stSidebar\"]').getAttribute('data-collapsed')"
    )
    if collapsed == "true":
        expand = pg.locator("[data-testid='stExpandSidebarButton']")
        if expand.count():
            expand.first.click(force=True)
            pg.wait_for_timeout(3000)
    option = pg.locator("[data-testid='stRadioOption']", has_text=name)
    option.first.scroll_into_view_if_needed(timeout=15000)
    option.first.click(force=True)
    pg.wait_for_timeout(3000)
    # at phone widths the bar is an overlay: leave it open and it swallows every later click on the page
    collapse = pg.locator("[data-testid='stSidebarCollapseButton']")
    if collapse.count() and width_is_narrow(pg):
        collapse.first.click(force=True)
        pg.wait_for_timeout(2500)


def width_is_narrow(pg) -> bool:
    return pg.evaluate("() => innerWidth < 760")


STRIP = """() => {
  const s = document.querySelector('.lm-strip');
  if (!s) return null;
  const box = s.getBoundingClientRect();
  const bw = parseFloat(getComputedStyle(s).borderTopWidth) || 0;
  const inner = box.height - bw * 2;
  const cells = [...s.querySelectorAll('.lm-cell')];
  // group by row, then measure the cells of the last row against the plate's bottom edge
  const rows = new Map();
  cells.forEach((c) => {
    const key = Math.round(c.getBoundingClientRect().top);
    if (!rows.has(key)) rows.set(key, []);
    rows.get(key).push(c);
  });
  const keys = [...rows.keys()].sort((a, b) => a - b);
  const lastRow = rows.get(keys[keys.length - 1]);
  // how far the last row of cells sits above the plate's inner bottom edge: 0 or 1 is flush
  const innerBottom = box.bottom - bw;
  const gaps = lastRow.map((c) => Math.round(innerBottom - c.getBoundingClientRect().bottom));
  return {lines: keys.length, lastRowGaps: gaps.slice(0, 4), cellCount: cells.length};
}"""


def live_controls(pg, width: int) -> None:
    """Press a row, clear it, page the feed, and check the page still responds afterwards."""
    pg.locator("[role='tab']", has_text="Alert feed").click(force=True)
    pg.wait_for_timeout(5000)
    rows = pg.locator(".st-key-lm_feed_stack button:not([disabled])")
    count = rows.count()
    check(f"{width}px Live: feed renders rows", count > 0, str(count))
    if not count:
        return
    check(f"{width}px Live: a row spans the feed", rows.nth(0).bounding_box()["width"] > 200, "narrow")
    check(f"{width}px Live: pressing a row works", soft_click(rows.nth(0), "feed row"))
    pg.wait_for_timeout(13000)
    selected = pg.evaluate(SELECTED)
    check(f"{width}px Live: pressing a row opens the trigger section", "trigger" in selected.lower(), selected)
    clear = pg.locator("button:visible", has_text="Clear")
    check(f"{width}px Live: Clear is offered", clear.count() > 0, "no button")
    if clear.count() and soft_click(clear, "Clear"):
        pg.wait_for_timeout(11000)
        after = pg.evaluate(SELECTED)
        check(f"{width}px Live: Clear returns to the feed", "feed" in after.lower(), after)
    soft_click(pg.locator("[role='tab']", has_text="Alert feed"), "feed tab")
    pg.wait_for_timeout(5000)
    step = pg.locator("[data-testid='stNumberInput'] button")
    if step.count():
        before = pg.locator(".st-key-lm_feed_stack button:not([disabled])").first.inner_text()
        soft_click(step.last, "page step")
        pg.wait_for_timeout(12000)
        moved = pg.locator(".st-key-lm_feed_stack button:not([disabled])").first.inner_text()
        check(f"{width}px Live: paging changes the rows", before != moved, before[:24])
    feed_pager(pg, width)
    m = pg.evaluate(METRICS)
    check(f"{width}px Live: no overflow after interaction", m["overflow"] <= 1, str(m["overflow"]))


def feed_pager(pg, width: int) -> None:
    """The flipper below the table: where it sits, that it moves the rows, and that both ends stop."""
    soft_click(pg.locator("[role='tab']", has_text="Alert feed"), "feed tab")
    pg.wait_for_timeout(6000)
    # earlier checks page the feed, so go back to page one deliberately: the end-of-range assertions are about
    # page one, not about wherever the last check happened to leave it
    box = pg.locator("[data-testid='stNumberInput'] input")
    box.first.fill("1")
    box.first.press("Enter")
    pg.wait_for_timeout(11000)
    g = pg.evaluate(PAGER)
    check(f"{width}px Live: pager exists below the table", "error" not in g, str(g)[:70])
    if "error" in g:
        return
    # the strip belongs to the table, so its ends are the table's ends and the position is centred on it
    check(f"{width}px Live: Previous sits on the table edge", g["leftGap"] <= 2, str(g["leftGap"]))
    check(f"{width}px Live: Next sits on the table edge", g["rightGap"] <= 2, str(g["rightGap"]))
    check(f"{width}px Live: page position is centred", g["centreGap"] <= 2, str(g["centreGap"]))
    check(f"{width}px Live: pager is outside the plate", g["below"] >= 0, str(g["below"]))
    check(f"{width}px Live: position shows current and total", "/" in g["text"], g["text"])
    check(f"{width}px Live: Previous is disabled on page one", g["prevOff"] is True, str(g["prevOff"]))

    pages = int(g["text"].split("/")[1])
    before = pg.locator(".st-key-lm_feed_stack button:not([disabled])").first.inner_text()
    nxt = pg.get_by_role("button", name="Next", exact=True)
    check(f"{width}px Live: Next is clickable", nxt.count() > 0 and not nxt.first.is_disabled(), str(nxt.count()))
    if nxt.count():
        nxt.first.click(force=True)
        pg.wait_for_timeout(11000)
        g2 = pg.evaluate(PAGER)
        moved = pg.locator(".st-key-lm_feed_stack button:not([disabled])").first.inner_text()
        check(f"{width}px Live: Next advances the position", g2.get("text") == f"2 / {pages}", str(g2.get("text")))
        check(f"{width}px Live: Next changes the rows", before != moved, moved[:24])
        check(f"{width}px Live: Previous wakes up", g2.get("prevOff") is False, str(g2.get("prevOff")))
        pg.get_by_role("button", name="Previous", exact=True).first.click(force=True)
        pg.wait_for_timeout(11000)
        back = pg.evaluate(PAGER)
        check(f"{width}px Live: Previous returns", back.get("text") == f"1 / {pages}", str(back.get("text")))

    if pages > 1:
        box = pg.locator("[data-testid='stNumberInput'] input")
        box.first.fill(str(pages))
        box.first.press("Enter")
        pg.wait_for_timeout(13000)
        last = pg.evaluate(PAGER)
        check(f"{width}px Live: Next is disabled on the last page", last.get("nextOff") is True, str(last)[:90])
        box.first.fill("1")
        box.first.press("Enter")
        pg.wait_for_timeout(11000)


def run() -> int:
    with sync_playwright() as p:
        browser = p.chromium.launch()
        for width in WIDTHS:
            ctx = browser.new_context(viewport={"width": width, "height": 1200}, device_scale_factor=1.2)
            pg, errors = watched_page(ctx)
            pg.goto(URL, wait_until="networkidle", timeout=90000)
            pg.wait_for_timeout(9000)
            for name in PAGES:
                goto_page(pg, name)
                pg.wait_for_timeout(9000 if name != "Results" else 11000)
                m = pg.evaluate(METRICS)
                check(f"{width}px {name}: no page overflow", m["overflow"] <= 1, f"{m['overflow']} {m['widest']}")
                check(f"{width}px {name}: main content has height", m["mainHeight"] > 400, str(m["mainHeight"]))
                check(f"{width}px {name}: nothing clipped in its box", not m["clipped"], str(m["clipped"]))
                tabs = pg.locator("[role='tab']")
                for i in range(tabs.count()):
                    label = tabs.nth(i).inner_text().strip()
                    if not soft_click(tabs.nth(i), f"{name}/{label} tab"):
                        continue
                    pg.wait_for_timeout(6000)
                    t = pg.evaluate(METRICS)
                    check(f"{width}px {name}/{label}: no overflow", t["overflow"] <= 1, str(t["overflow"]))
                    check(f"{width}px {name}/{label}: renders", t["mainHeight"] > 300, str(t["mainHeight"]))
                    check(f"{width}px {name}/{label}: nothing clipped", not t["clipped"], str(t["clipped"]))
                    check(
                        f"{width}px {name}/{label}: becomes selected",
                        tabs.nth(i).get_attribute("aria-selected") == "true",
                        label,
                    )
                strip = pg.evaluate(STRIP)
                if strip:
                    # with one row, every cell must reach the plate's bottom edge: that is the invariant the
                    # <dl> margin used to break. When the strip wraps, each row is its own line and only the
                    # last row can reach the bottom, so the invariant there is "the last row reaches it".
                    if strip["lines"] == 1:
                        check(f"{width}px {name}: strip cells fill the plate", all(g <= 1 for g in strip["lastRowGaps"]),
                              str(strip["lastRowGaps"]))
                    else:
                        check(f"{width}px {name}: wrapped strip still lights to the bottom",
                              all(g <= 1 for g in strip["lastRowGaps"]), str(strip["lastRowGaps"]))
                if name == "Live":
                    al = pg.evaluate(FEED_ALIGN)
                    check(f"{width}px Live: feed header sits over its columns",
                          al.get("worst", 99) <= 1.0, str(al)[:120])
                prose = pg.evaluate(PROSE)
                check(f"{width}px {name}: prose is not width-capped", not prose["capped"], str(prose["capped"]))
                if name == "Live":
                    live_controls(pg, width)
                    goto_page(pg, "Live")
                    pg.wait_for_timeout(6000)
                check(f"{width}px {name}: no console errors", not errors, errors[0] if errors else "")
            ctx.close()
        browser.close()
    print("-" * 60)
    print(f"{PASSED} passed, {len(FAILURES)} failed")
    for line in FAILURES:
        print("  " + line)
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(run())
