"""Live detector: score DNS queries as they are seen and write alerts to live/alerts.db.

    python -m live --pcap data/raw/tools/<capture>.pcap           # replay a capture, no root needed
    python -m live --pcap <capture>.pcap --speed 1                # ... at the recorded pace
    sudo python -m live --iface ip:172.28.0.2                     # sniff the interface holding that address
    python -m live --iface eth0 --model <name> --weights <file>   # another model: models/<name>.py and its save()
    live/run_live.sh                                              # the same, inside the testbed (see live/README.md)
    python -m live.report                                         # what a run detected and how fast (live/report.py)

With no --model it runs M1, the selected model, from artifacts/m1_xgb/E1.pt (live/README.md says how to get
that file). --model dummy is a placeholder scorer (name length only) for testing the pipeline without a model.
"""

from __future__ import annotations

import argparse
import signal

from live.capture import find_interface, pcap_frames, sniff_frames
from live.pipeline import Detector, QueryAssembler, run
from live.scorers import DEFAULT_MODEL, M1_WEIGHTS, load_scorer
from live.store import AlertStore
from models import m1_features
from parser.testbed import RESOLVER


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(
        prog="python -m live", description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--iface", help="interface to sniff: a name (eth0), or ip:<address> for the one holding it")
    src.add_argument("--pcap", help="replay this capture file instead of sniffing")
    ap.add_argument(
        "--speed", type=float, default=0.0, help="with --pcap: 0 = as fast as possible (default), 1 = real time"
    )
    ap.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help=f"{DEFAULT_MODEL} (default), any models/<name>.py, or dummy (placeholder, not a detector)",
    )
    ap.add_argument(
        "--weights", help=f"file written by that model's save() (default for m1: {M1_WEIGHTS}; dummy needs none)"
    )
    ap.add_argument(
        "--threshold", type=float, help="alert when score >= this (default: the model's own; required if it has none)"
    )
    ap.add_argument("--db", default="live/alerts.db", help="SQLite file to append alerts to")
    ap.add_argument(
        "--ignore-src",
        action="append",
        help=f"drop queries sent by this address; repeatable (default: the resolver, {RESOLVER}, "
        "whose forwarded copies would count each lookup twice). Pass 'none' to drop nothing",
    )
    ap.add_argument("--window", type=float, default=m1_features.DEFAULT_CFG["window_s"], help="host window, seconds")
    ap.add_argument(
        "--reply-wait", type=float, default=1.0, help="seconds to wait for a query's reply before scoring it"
    )
    ap.add_argument("--batch", type=float, default=0.5, help="seconds of traffic scored together")
    a = ap.parse_args(argv)

    ignore = [RESOLVER] if a.ignore_src is None else [s for s in a.ignore_src if s != "none"]
    scorer = load_scorer(a.model, a.weights, a.threshold)
    if a.pcap:
        # mode: only a sniffed packet's timestamp is on the wall clock, so only then is there a time to alert
        source, where, mode = pcap_frames(a.pcap, a.speed), a.pcap, "replay"
    else:
        where = find_interface(a.iface)
        source, mode = sniff_frames(where), "sniff"
    store = AlertStore(a.db, model=scorer.name, threshold=scorer.threshold, source=where, mode=mode)
    print(
        f"live: {where} -> {a.db} | model {scorer.name}, alert at score >= {scorer.threshold} | ignoring {ignore}",
        flush=True,
    )
    signal.signal(signal.SIGTERM, signal.default_int_handler)  # `docker stop` ends the run like Ctrl+C does
    try:
        run(source, QueryAssembler(ignore, a.reply_wait), Detector(scorer, store, a.window), a.batch)
    finally:
        store.close()


if __name__ == "__main__":
    main()
