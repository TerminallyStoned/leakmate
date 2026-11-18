"""Live sniffer: score DNS queries as they are seen and write alerts to live/alerts.db.

    python -m live --pcap data/raw/tools/<capture>.pcap           # replay a capture, no root needed
    python -m live --pcap <capture>.pcap --speed 1                # ... at the recorded pace
    sudo python -m live --iface ip:172.28.0.2                     # sniff the interface holding that address
    python -m live --iface eth0 --model m1 --weights <m1.joblib>  # a trained model instead of the placeholder
    live/run_live.sh                                              # the same, inside the testbed (see live/README.md)

The default scorer is a placeholder (name length only). It is there to exercise the pipeline, not to detect.
"""

from __future__ import annotations

import argparse
import signal

from live.capture import find_interface, pcap_frames, sniff_frames
from live.pipeline import Detector, QueryAssembler, run
from live.scorers import load_scorer
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
    ap.add_argument("--model", default="dummy", help="dummy (default), m1, or any models/<name>.py")
    ap.add_argument("--weights", help="file written by that model's save(); needed for every model but dummy")
    ap.add_argument("--threshold", type=float, help="alert when score >= this (default: the model's own, else 0.5)")
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
        source, where = pcap_frames(a.pcap, a.speed), a.pcap
    else:
        where = find_interface(a.iface)
        source = sniff_frames(where)
    store = AlertStore(a.db, model=scorer.name, threshold=scorer.threshold, source=where)
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
