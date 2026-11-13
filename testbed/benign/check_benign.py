#!/usr/bin/env python3
"""Acceptance check for the benign generator (Trello card 7: "one 10-minute run gives
more than 5k benign queries that parse cleanly").

Reads the sidecar(s) written by ``generate.py`` and reports whether the run clears the
bar. "Parses cleanly" here means every emitted name is a syntactically valid query name;
the parser (card 9) owns the pcap side of the same claim.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Iterable, Iterator

sys.path.insert(0, str(Path(__file__).resolve().parent))

import domains as dom  # noqa: E402

REQUIRED = ("ts", "src_host", "qname", "qtype", "label", "tool", "dataset")
CDN_HINT = re.compile(r"(cloudfront|akamai|akamaized|akadns|azureedge|edgekey|edgesuite|fastly|cdn77|cdnbuild|gcdn|cloudflare|core\.windows|s3\.amazonaws|storage\.googleapis)\.")


def iter_rows(paths: Iterable[Path], problems: list[str] | None = None) -> Iterator[dict[str, object]]:
    """Yield sidecar rows.

    Unreadable files warn on stderr; malformed *lines* are counted and appended to
    *problems*, because a truncated line is how two writers on one sidecar shows up and a
    checker that dropped them quietly would certify corrupted data.
    """
    for path in sorted(paths):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            print(f"WARN cannot read {path}: {exc}", file=sys.stderr)
            continue
        malformed = 0
        if path.suffix == ".csv":
            yield from _parse_csv(text)
        else:
            for lineno, line in enumerate(text.splitlines(), 1):
                row = _parse_line(path, lineno, line.strip())
                if row is None:
                    malformed += 1
                    continue
                yield row
        if malformed and problems is not None:
            problems.append(
                f"{path.name}: {malformed} malformed line(s) — sidecar corrupted, "
                "usually two hosts writing one file (check --src-host is unique)"
            )


def _parse_csv(text: str) -> Iterator[dict[str, object]]:
    try:
        yield from csv.DictReader(text.splitlines())
    except csv.Error as exc:
        print(f"WARN this file is not valid CSV: {exc}", file=sys.stderr)


def _parse_line(path: Path, lineno: int, line: str) -> dict[str, object] | None:
    if not line:
        return None
    try:
        parsed = json.loads(line)
    except json.JSONDecodeError:
        print(f"WARN {path}:{lineno} is not JSON, skipped", file=sys.stderr)
        return None
    if not isinstance(parsed, dict):
        print(f"WARN {path}:{lineno} is not an object, skipped", file=sys.stderr)
        return None
    return parsed


def _as_num(value: object) -> float | None:
    """Contract columns arrive as str/int/float depending on format; None when unusable."""
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return None


def _to_num(value: object) -> float | None:
    try:
        return _as_num(value)
    except Exception as exc:  # pragma: no cover - defensive: exotic scalar type in sidecar
        print(f"WARN cannot convert ts/label value {value!r}: {exc}", file=sys.stderr)
        return None


def check(paths: Iterable[Path], min_queries: int, window_minutes: float, min_hosts: int) -> tuple[list[str], dict[str, object]]:
    """Return (problems, stats) for the sidecar rows under *paths*."""
    problems: list[str] = []
    rows = list(iter_rows(paths, problems))
    hosts: Counter[str] = Counter()
    engines: Counter[str] = Counter()
    qtypes: Counter[str] = Counter()
    names: set[str] = set()
    bad: list[str] = []
    ts_min: float | None = None
    ts_max: float | None = None
    non_benign = 0
    bad_ts = 0

    for row in rows:
        missing = [col for col in REQUIRED if row.get(col) in (None, "")]
        if missing:
            problems.append(f"row missing contract columns {missing}: {row}")
            continue
        name = str(row["qname"])
        if not dom.is_valid_fqdn(name):
            bad.append(name)
        names.add(name)
        hosts[str(row["src_host"])] += 1
        engines[str(row.get("engine") or "?")] += 1
        qtypes[str(row["qtype"])] += 1
        label = _to_num(row["label"])
        if str(row["tool"]) != "benign" or label != 0.0:
            non_benign += 1
        ts = _to_num(row["ts"])
        if ts is None:
            bad_ts += 1
            continue
        ts_min = ts if ts_min is None else min(ts_min, ts)
        ts_max = ts if ts_max is None else max(ts_max, ts)

    if bad_ts:
        problems.append(f"{bad_ts} rows have a non-numeric ts")

    if len(rows) < min_queries:
        problems.append(f"{len(rows)} rows is below the required {min_queries} benign queries")
    if bad:
        problems.append(f"{len(bad)} names fail DNS syntax, e.g. {bad[:3]}")
    if non_benign:
        problems.append(f"{non_benign} rows are not label=0/tool=benign")
    if len(hosts) < min_hosts:
        problems.append(f"only {len(hosts)} distinct src_host values, expected >= {min_hosts}")
    if ts_min is not None and ts_max is not None:
        span = ts_max - ts_min
        if span < window_minutes * 60.0 * 0.9:
            problems.append(f"ts span is {span:.0f}s, shorter than the {window_minutes:.0f}-minute window")
    if not engines.get("cdn") and not any(CDN_HINT.search(n) for n in names):
        problems.append("no CDN / cloud hostnames in the run — DNS-BERT false positives will not be covered")

    span = (ts_max - ts_min) if ts_min is not None and ts_max is not None else 0.0
    stats = {
        "rows": len(rows),
        "distinct_qnames": len(names),
        "hosts": dict(hosts),
        "engines": dict(engines),
        "qtypes": dict(qtypes),
        "span_s": round(span, 1),
        "qps": round(len(rows) / span, 2) if span > 0 else 0.0,
        "cdn_share": round(sum(1 for n in names if CDN_HINT.search(n)) / max(1, len(names)), 3),
    }
    return problems, stats


def resolve_paths(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    return sorted(list(target.glob("*.ndjson")) + list(target.glob("*.csv")))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("path", type=Path, help="sidecar file or directory of sidecars")
    p.add_argument("--min-queries", type=int, default=5000, help="card 7 done-when: >5k benign queries")
    p.add_argument("--window-minutes", type=float, default=10.0, help="expected run window")
    p.add_argument("--min-hosts", type=int, default=2, help="per-host window features need variety")
    p.add_argument("--json", action="store_true", help="print stats as JSON only")
    args = p.parse_args(argv)

    paths = resolve_paths(args.path)
    if not paths:
        print(f"FAIL no sidecar found under {args.path}", file=sys.stderr)
        return 2

    problems, stats = check(paths, args.min_queries, args.window_minutes, args.min_hosts)
    if args.json:
        print(json.dumps({"ok": not problems, "stats": stats, "problems": problems}, indent=2, sort_keys=True))
    else:
        print(json.dumps(stats, indent=2, sort_keys=True))
        if problems:
            print("\n".join(f"FAIL {p}" for p in problems), file=sys.stderr)
        else:
            print(f"PASS {stats['rows']} benign queries over {stats['span_s']:.0f}s from {len(stats['hosts'])} hosts")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
