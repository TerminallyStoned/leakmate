#!/usr/bin/env python3
"""Merge sidecar NDJSON and parsed captures into the Parquet query table.

    python3 scripts/build_queries_parquet.py --dataset testbed \\
        --add data/raw/benign/<run id> \\
        --add data/raw/tools/dns2tcp_<utc> \\
        --out data/processed/testbed/queries.parquet

`--add` takes a directory of NDJSON rows (a benign run writes `<ip>.ndjson` sidecars,
`run_tool.sh --capture` writes `<tool>.ndjson` next to its pcap) or a single `.ndjson`
file; repeat it. Earlier sources win, so pass the capture first: its `resp_size`/`rcode`
are what the resolver really answered, while a sidecar only knows about the lookups it
issued with `dig`.

Pass exactly one source per capture window. A benign sidecar and the pcap of that same run
are two views of one traffic, and their rows do not share a timestamp - measured 44 ms
apart in this lab, because the sidecar stamps when a lookup is planned and the pcap stamps
when it reaches the wire, with `dig` in between. Fuzzy-merging them lost 34% of one source
when tried, so instead the script concatenates and warns loudly when two sources overlap.

STOPGAP, same status as scripts/cic_to_queries.py: the parser card (#9) owns this join
and this file retires when it lands. Output columns and their order are the CONTRACTS
card's query table, which is what eval/experiments.py:load_queries() reads.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

COLUMNS = ("ts", "src_host", "session_id", "qname", "qtype", "resp_size", "rcode",
           "label", "tool", "dataset", "throttle")


def _sources(path: Path) -> list[Path]:
    if path.is_dir():
        files = sorted(path.glob("*.ndjson"))
        if not files:
            raise SystemExit(f"{path}: no .ndjson rows under it")
        return files
    if path.suffix in (".ndjson", ".json"):
        return [path]
    raise SystemExit(f"{path}: expected a directory of .ndjson or one .ndjson file")


def _trip(row: dict) -> tuple:
    return (row["src_host"], str(row["qname"]).lower(), row["qtype"])


def merge(paths: list[Path], dataset: str, tolerance: float = 0.5) -> tuple[list[dict], dict[str, int]]:
    """Rows from *paths*, concatenated, sorted by time, exact duplicates dropped.

    `tolerance` is only used by the overlap guard, never to decide what to drop: a benign
    sidecar and the capture of the same run cannot be told apart from two genuinely identical
    lookups, because a sidecar stamps plan time and a pcap stamps wire time and that gap is
    `dig` latency (44 ms typical here, with a tail over half a second). Fuzzy matching lost
    34% of one source when tried, so the rule is honest instead of clever: one source per
    capture window, and the guard shouts if you break it.
    """
    kept: list[dict] = []
    seen: set[tuple] = set()
    stats = {"read": 0, "duplicates": 0, "bad_lines": 0, "wrong_dataset": 0}
    windows: list[tuple[Path, dict[str, list[float]]]] = []
    for p in paths:
        span: dict[str, list[float]] = {}
        for lineno, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
                row["ts"] = float(row["ts"])
            except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                stats["bad_lines"] += 1
                print(f"WARN {p}:{lineno} unreadable row, skipped", file=sys.stderr)
                continue
            stats["read"] += 1
            if row.get("dataset", dataset) != dataset:
                stats["wrong_dataset"] += 1  # keeps a cic/ table from absorbing testbed rows
                continue
            row["dataset"] = dataset
            row["throttle"] = row.get("throttle") or ""  # mixed str/None breaks pyarrow's type inference
            trip = _trip(row)
            span.setdefault(trip, []).append(row["ts"])
            key = (trip, round(row["ts"], 6))
            if key in seen:
                stats["duplicates"] += 1
                continue
            seen.add(key)
            kept.append({c: row.get(c) for c in COLUMNS})
        windows.append((p, span))
    _warn_overlap(windows, tolerance)
    kept.sort(key=lambda r: (r["ts"], r["src_host"]))
    return kept, stats


def _warn_overlap(windows: list[tuple[Path, dict[str, list[float]]]], tolerance: float) -> None:
    """Two sources covering the same lookups would double-count the run."""
    for i in range(len(windows)):
        for j in range(i + 1, len(windows)):
            (pa, sa), (pb, sb) = windows[i], windows[j]
            shared = [t for t in sa if t in sb and any(abs(a - b) <= tolerance for a in sa[t] for b in sb[t])]
            if len(shared) >= 0.5 * min(len(sa), len(sb)):
                print(
                    f"WARN {pa.name} and {pb.name} describe {len(shared)} of the same lookups - "
                    "these are two views of one capture window; pass only one of them, or the "
                    "table double-counts every query",
                    file=sys.stderr,
                )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--add", action="append", type=Path, required=True, dest="adds")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--dataset", default="testbed", choices=("testbed", "cic"))
    ap.add_argument("--tolerance", type=float, default=0.5,
                    help="seconds within which two sources count as the same capture window")
    args = ap.parse_args(argv)

    files = [f for a in args.adds for f in _sources(a)]
    rows, stats = merge(files, args.dataset, args.tolerance)
    if not rows:
        raise SystemExit("nothing to write: every row was a duplicate or belonged to another dataset")

    import pandas as pd  # noqa: PLC0415 - the only heavy import, needed for the write

    args.out.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows, columns=list(COLUMNS)).to_parquet(args.out, index=False)
    tools = sorted({r["tool"] for r in rows})
    print(
        f"wrote {len(rows)} rows to {args.out} "
        f"(read {stats['read']}, duplicates dropped {stats['duplicates']}, "
        f"other-dataset rows {stats['wrong_dataset']}, bad lines {stats['bad_lines']}; tools: {tools})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
