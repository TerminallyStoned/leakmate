"""CIC-Bell-DNS-EXF-2021 pcaps -> contract query table (STOPGAP for M2).

The parser card (Yehan) owns the real parser. This only exists so M2 is not
blocked. Output: one row per DNS query (client -> port 53) in the contract
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

  python scripts/cic_to_queries.py --raw data/raw/cic --out data/processed/cic/queries.parquet
"""
from __future__ import annotations

import argparse
import re
import socket
import sys
from pathlib import Path

import dpkt
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from contracts import assign_sessions, qtype_name, validate_queries  # noqa: E402

EXFIL = re.compile(r"^(init\.[A-Za-z2-7]{8,}|\d+\.[A-Za-z0-9_-]{8,})")


def _qname(raw: bytes):
    """Tolerant qname parse. Returns (qname, truncated, offset_after_name)."""
    i, labels = 12, []
    while i < len(raw):
        n = raw[i]
        if n == 0:
            return ".".join(labels), False, i + 1
        if n & 0xC0:  # compression pointer never appears in a question; treat as malformed
            return ".".join(labels), True, None
        if i + 1 + n > len(raw):
            labels.append(raw[i + 1:].decode("latin1"))
            return ".".join(labels), True, None
        labels.append(raw[i + 1:i + 1 + n].decode("latin1"))
        i += 1 + n
    return ".".join(labels), True, None


def _addr(ip):
    return socket.inet_ntop(socket.AF_INET6 if isinstance(ip, dpkt.ip6.IP6) else socket.AF_INET, ip.src), \
        socket.inet_ntop(socket.AF_INET6 if isinstance(ip, dpkt.ip6.IP6) else socket.AF_INET, ip.dst)


def parse_pcap(path: Path, is_attack: bool) -> pd.DataFrame:
    queries, pending = [], {}
    with open(path, "rb") as f:
        for ts, buf in dpkt.pcap.Reader(f):
            try:
                ip = dpkt.ethernet.Ethernet(buf).data
                if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)) or not isinstance(ip.data, dpkt.udp.UDP):
                    continue
                u = ip.data
                if 53 not in (u.sport, u.dport):
                    continue
                raw = bytes(u.data)
                if len(raw) < 12:
                    continue
                txid, flags = int.from_bytes(raw[0:2], "big"), int.from_bytes(raw[2:4], "big")
                src, dst = _addr(ip)
                is_resp = bool(flags & 0x8000)
                if not is_resp and u.dport == 53:
                    q, trunc, off = _qname(raw)
                    if not q:
                        continue
                    qt = int.from_bytes(raw[off:off + 2], "big") if off and off + 2 <= len(raw) else None
                    exfil = is_attack and bool(EXFIL.match(q))
                    key = (src, u.sport, txid)
                    if key in pending:  # retransmission of a query still awaiting an answer
                        continue
                    pending[key] = len(queries)
                    queries.append(dict(ts=float(ts), src_host=src, qname=q, qtype=qtype_name(qt),
                                        resp_size=0, rcode=-1, label=int(exfil),
                                        tool="dnsexfiltrator" if exfil else "benign",
                                        qname_truncated=trunc, qlen_wire=u.ulen - 8))
                elif is_resp and u.sport == 53:
                    idx = pending.pop((dst, u.dport, txid), None)
                    if idx is not None:
                        queries[idx]["resp_size"] = u.ulen - 8
                        queries[idx]["rcode"] = flags & 0xF
            except (dpkt.UnpackError, ValueError, IndexError):
                continue  # malformed packet
    df = pd.DataFrame(queries)
    if df.empty:
        return df
    df["source_file"] = f"{path.parent.parent.name}/{path.name}"
    return df


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", default="data/raw/cic")
    ap.add_argument("--out", default="data/processed/cic/queries.parquet")
    ap.add_argument("--train-frac", type=float, default=0.7)
    a = ap.parse_args()
    parts = []
    for p in sorted(Path(a.raw).rglob("*.pcap")):
        is_attack = "attack" in str(p).lower()
        df = parse_pcap(p, is_attack)
        if df.empty:
            continue
        df = df.sort_values("ts", kind="stable").reset_index(drop=True)
        df["split"] = ["train" if i < int(len(df) * a.train_frac) else "test" for i in range(len(df))]
        parts.append(df)
        print(f"{p}: {len(df)} queries, {int(df.label.sum())} exfil, {int(df.qname_truncated.sum())} truncated")
    out = pd.concat(parts, ignore_index=True)
    out["dataset"], out["throttle"] = "cic", 0
    out["session_id"] = assign_sessions(out)
    validate_queries(out)
    cols = ["ts", "src_host", "session_id", "qname", "qtype", "resp_size", "rcode", "label", "tool", "dataset",
            "throttle", "qname_truncated", "qlen_wire", "source_file", "split"]
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    out[cols].to_parquet(a.out, index=False)
    print(f"-> {a.out}: {len(out)} rows | label=1: {int(out.label.sum())} | "
          f"train {int((out.split == 'train').sum())} / test {int((out.split == 'test').sum())}")


if __name__ == "__main__":
    main()
