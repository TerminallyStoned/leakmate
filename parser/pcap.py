"""Shared pcap reader for CIC and testbed captures: one row per DNS query, contract columns.

Both datasets go through this one reader so E4 (cross-dataset) compares traffic, not two
parsers' quirks. Only labelling differs: the caller passes tool_of(src_host, qname).
"""

from __future__ import annotations

import socket
import sys
from collections.abc import Callable
from pathlib import Path

import dpkt
import pandas as pd

from contracts import assign_sessions, qtype_name, validate_queries

COLS = [
    "ts",
    "src_host",
    "session_id",
    "qname",
    "qtype",
    "resp_size",
    "rcode",
    "label",
    "tool",
    "dataset",
    "throttle",
    "qname_truncated",
    "qlen_wire",
    "source_file",
    "split",
]


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
            if raw[i + 1 :]:  # cut right after a length byte leaves an empty label: drop it (no trailing dot)
                labels.append(raw[i + 1 :].decode("latin1"))
            return ".".join(labels), True, None
        labels.append(raw[i + 1 : i + 1 + n].decode("latin1"))
        i += 1 + n
    return ".".join(labels), True, None


def _addr(ip):
    return socket.inet_ntop(
        socket.AF_INET6 if isinstance(ip, dpkt.ip6.IP6) else socket.AF_INET, ip.src
    ), socket.inet_ntop(socket.AF_INET6 if isinstance(ip, dpkt.ip6.IP6) else socket.AF_INET, ip.dst)


def _packets(f, path: Path):
    """dpkt's reader, but a torn last record (tcpdump killed mid-write) ends the file instead of raising."""
    it = iter(dpkt.pcap.Reader(f))
    while True:
        try:
            yield next(it)
        except StopIteration:
            return
        except dpkt.NeedData:
            print(f"WARN {path}: dropped a partial last record (capture stopped mid-write)", file=sys.stderr)
            return


def parse_pcap(path: Path, tool_of: Callable[[str, str], str | None]) -> pd.DataFrame:
    """Queries (client -> port 53) in path, each with its reply's size and rcode if one was captured.

    Malformed packets are skipped; a query retransmitted before its reply arrived is kept once.
    tool_of(src_host, qname) returns the tool name, "benign", or None to skip that query."""
    queries, pending = [], {}
    with open(path, "rb") as f:
        for ts, buf in _packets(f, path):
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
                    qt = int.from_bytes(raw[off : off + 2], "big") if off and off + 2 <= len(raw) else None
                    tool = tool_of(src, q)
                    if tool is None:  # caller drops this sender, e.g. the resolver's forwarded copies
                        continue
                    key = (src, u.sport, txid)
                    if key in pending:  # retransmission of a query still awaiting an answer
                        continue
                    pending[key] = len(queries)
                    queries.append(
                        dict(
                            ts=float(ts),
                            src_host=src,
                            qname=q,
                            qtype=qtype_name(qt),
                            resp_size=0,
                            rcode=-1,
                            label=int(tool != "benign"),
                            tool=tool,
                            qname_truncated=trunc,
                            qlen_wire=u.ulen - 8,
                        )
                    )
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


def with_split(df: pd.DataFrame, train_frac: float) -> pd.DataFrame:
    """One capture's rows in time order, first train_frac -> "train", rest -> "test"."""
    df = df.sort_values("ts", kind="stable").reset_index(drop=True)
    df["split"] = ["train" if i < int(len(df) * train_frac) else "test" for i in range(len(df))]
    return df


def finish(parts: list[pd.DataFrame], dataset: str) -> pd.DataFrame:
    """Per-capture tables (with throttle and split set) -> one validated query table (columns COLS)."""
    out = pd.concat(parts, ignore_index=True)
    out["dataset"] = dataset
    out["session_id"] = assign_sessions(out)
    validate_queries(out)
    return out[COLS]
