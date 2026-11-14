"""CIC-Bell-DNS-EXF-2021 pcaps -> contract query table.

Output: one row per DNS query (client -> port 53) in the contract
schema (docs/contracts.md), plus `qname_truncated`, `qlen_wire`, `source_file`, `split`.
qtype is the mnemonic, TYPE<n> for unmapped codes, UNKNOWN when snaplen cut it off.
session_id is `<source_file>|<src_host>|<k>`, k growing after a 30-min idle gap.

CIC CAVEAT: the pcaps were captured with snaplen=96, so each packet keeps only
~40 bytes of the query name. Most benign names fit; nearly every exfiltration
name is cut. `qname` here is what survives; `qlen_wire` (UDP payload length of
the query) still gives the true size. Feature code must not use len(qname) as
the query length on CIC.

Labels (DNSExfiltrator is the only attack tool in CIC):
  attack pcaps: `init.<base32>...` or `<n>.<base64url>...` -> label 1, tool=dnsexfiltrator;
                anything else (Windows background lookups)  -> label 0, tool=benign
  benign pcaps: label 0

Split: per capture file, first 70% of queries by time -> train, rest -> test
(time-based, never shuffled rows).

Malformed packets are skipped; a query retransmitted before its reply arrived is kept once.

  python -m parser cic --raw data/raw/cic --out data/processed/cic/queries.parquet
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import pandas as pd

from parser.pcap import _qname, finish, parse_pcap, with_split  # noqa: F401  (_qname: old import path)

EXFIL = re.compile(r"^(init\.[A-Za-z2-7]{8,}|\d+\.[A-Za-z0-9_-]{8,})")


def build(raw: str | Path, train_frac: float = 0.7) -> pd.DataFrame:
    """Every *.pcap under raw -> one validated query table (columns parser.pcap.COLS)."""
    parts = []
    for p in sorted(Path(raw).rglob("*.pcap")):
        # raw's own name and the folders under it count, folders above raw do not
        is_attack = "attack" in f"{Path(raw).resolve().name}/{p.relative_to(raw)}".lower()
        df = parse_pcap(p, lambda _src, q, a=is_attack: "dnsexfiltrator" if a and EXFIL.match(q) else "benign")
        if df.empty:
            continue
        df = with_split(df, train_frac)
        df["throttle"] = 0
        parts.append(df)
        print(f"{p}: {len(df)} queries, {int(df.label.sum())} exfil, {int(df.qname_truncated.sum())} truncated")
    if not parts:
        raise SystemExit(f"no DNS queries in any *.pcap under {raw}")
    return finish(parts, "cic")


def main(argv: list[str] | None = None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", default="data/raw/cic")
    ap.add_argument("--out", default="data/processed/cic/queries.parquet")
    ap.add_argument("--train-frac", type=float, default=0.7)
    a = ap.parse_args(argv)
    out = build(a.raw, a.train_frac)
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    out.to_parquet(a.out, index=False)
    print(
        f"-> {a.out}: {len(out)} rows | label=1: {int(out.label.sum())} | "
        f"train {int((out.split == 'train').sum())} / test {int((out.split == 'test').sum())}"
    )
