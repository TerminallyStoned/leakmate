#!/usr/bin/env python3
"""Turn a lab pcap into rows of the contract query table.

Card #8's acceptance is "a 1-minute capture of each tool parses with the parser". The
group parser (card #9) does this for CIC and is not merged yet, so this script is the
stand-in that proves the captures are usable: the output is the CONTRACTS column list,
in the same order, so card #9 can drop its own reader in without touching a caller.

    python3 scripts/parse_capture.py CAPTURE.pcap --out rows.ndjson --tool dnsexfiltrator
    python3 scripts/parse_capture.py CAPTURE.pcap --summary

Each sidecar row is one DNS query seen on the wire. `label` is 1 when the query came from
a tool address (--tools-map, or --tool with the lab's default), because in the testbed the
source host *is* the label. `resp_size` and `rcode` come from the matching reply when the
capture holds it, so they are the resolver's own answers rather than a client's guess.

Only responses' sizes matter for the models, and a query has no size of its own, so
`resp_size` is the DNS payload length of the reply (bytes of DNS message, as tcpdump
counted it), which is what the parser card records too.
"""

from __future__ import annotations

import argparse
import json
import socket
import struct
import sys
from pathlib import Path

import dpkt
import dpkt.dns as dns

# The CONTRACTS card's column order. Extra columns are appended, never reordered.
COLUMNS = (
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
)

QTYPE = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    65: "HTTPS",
}
RCODE = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}

_MAGICS = (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")

# Lab addresses assigned in testbed/docker-compose.yml and testbed/tools/docker-compose.yml.
# The benign generator labels itself with its own IP, so it is not listed here on purpose:
# a row from an unmapped address with --tool set is still labelled, which is the safe
# default for a capture taken during a tool run.
LAB_IPS = {
    "172.28.0.41": "dnsexfiltrator",
    "172.28.0.43": "dnsexfiltrator",
    "172.28.0.42": "dns2tcp",
    "172.28.0.44": "dns2tcp",
}


def _frames(fh):
    """Yield (timestamp, frame) from an open pcap, stopping at a partial trailing record.

    tcpdump killed by SIGTERM can leave a torn last record - a 12-byte header with no body.
    Reading it with the whole file open raises dpkt.dpkt.NeedData and would abort the parse
    of an otherwise good capture, so the tail is dropped loudly instead.
    """
    buf = fh.read()
    if len(buf) < 24:
        raise SystemExit("pcap is shorter than its 24-byte global header")
    if buf[:4] not in _MAGICS:
        raise SystemExit(f"{buf[:4]!r} is not a classic pcap magic; convert with: tcpdump -r in.pcapng -w out.pcap")
    big = buf[:4] in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d")
    fmt = ">IIII" if big else "<IIII"
    off, n, dropped = 24, 0, 0
    while off + 16 <= len(buf):
        secs, usec, caplen, _orig = struct.unpack(fmt, buf[off : off + 16])
        if caplen > 262144 or off + 16 + caplen > len(buf):
            dropped = len(buf) - off
            break
        yield secs + usec * 1e-6, buf[off + 16 : off + 16 + caplen]
        off += 16 + caplen
        n += 1
    if dropped:
        print(f"WARN dropped a trailing {dropped}-byte partial record (capture killed mid-write)", file=sys.stderr)


def _ipv4(raw: bytes) -> str:
    return socket.inet_ntoa(raw)


def _qname(q) -> str:
    """Decoded query name, lower-cased, no trailing dot."""
    return str(q.name).lower().rstrip(".")


def parse_pcap(path: Path, tools: dict[str, str], dataset: str, throttle: str, stats: dict | None = None) -> list[dict]:
    """Return one dict per DNS query in *path*, oldest first.

    Raises nothing: a frame that is not DNS is skipped, since tcpdump on a busy lab
    interface also carries ARP, DHCP and the resolver's own traffic. A frame cut short by
    the capture snaplen is read as far as it goes (`dpkt.dns.DNS` tolerates the truncated
    payload), because the question section - the part models use - arrives first.
    """
    def bump(key: str) -> None:
        if stats is not None:
            stats[key] = stats.get(key, 0) + 1

    # Pass 1: index replies by DNS transaction id so queries can carry their answer.
    replies: dict[int, tuple[int, int]] = {}
    with path.open("rb") as fh:
        for _ts, buf in _frames(fh):
            dns_payload = _dns_payload(buf)
            if dns_payload is None:
                continue
            bump("frames")
            try:
                msg = dns.DNS(dns_payload)
            except Exception:
                bump("truncated")
                continue
            if not msg.qd:
                continue
            # msg.qr is the decoded 0/1 field, not the 0x8000 header bit, so compare on
            # truthiness: `== dns.DNS_QR` (32768) silently matched nothing and lost every reply.
            if msg.qr:
                replies[msg.id] = (len(dns_payload), msg.rcode)

    # Pass 2: emit the queries.
    rows: list[dict] = []
    with path.open("rb") as fh:
        for ts, buf in _frames(fh):
            src, payload = _query_source(buf)
            if payload is None:
                continue
            try:
                msg = dns.DNS(payload)
            except Exception:
                bump("truncated")  # already counted in pass 1; pass 2 mirrors it
                continue
            if msg.qr or not msg.qd:
                continue
            q = msg.qd[0]
            # None is legitimate when the capture ended before the reply arrived.
            size, rcode = replies.get(msg.id, (None, None))  # pi-lens-ignore: unchecked-numeric-parse-python
            tool = tools.get(src, "")
            bump("queries")
            rows.append(
                {
                    "ts": round(float(ts), 6),
                    "src_host": src,
                    "session_id": f"{src}-{len(rows)}",
                    "qname": _qname(q),
                    "qtype": QTYPE.get(q.type, str(q.type)),
                    "resp_size": size,
                    "rcode": RCODE.get(rcode, str(rcode)) if rcode is not None else None,
                    # In the testbed the source host is the label: a tool address means tunnel.
                    "label": 1 if tool else 0,
                    "tool": tool or "benign",
                    "dataset": dataset,
                    "throttle": throttle,
                }
            )
    return rows


def _dns_payload(buf: bytes):
    """The UDP payload of an IPv4/UDP frame, or None if the frame is not one."""
    try:
        ip = dpkt.ethernet.Ethernet(buf).data
        if getattr(ip, "p", None) != dpkt.ip.IP_PROTO_UDP:
            return None
        udp = ip.data
        if not isinstance(udp, dpkt.udp.UDP):
            return None
        return bytes(udp.data) or None
    except Exception:
        return None


def _query_source(buf: bytes) -> tuple[str, bytes | None]:
    """(source address, DNS payload) for a frame carrying a query to port 53."""
    try:
        ip = dpkt.ethernet.Ethernet(buf).data
        if getattr(ip, "p", None) != dpkt.ip.IP_PROTO_UDP:
            return "", None
        udp = ip.data
        if not isinstance(udp, dpkt.udp.UDP) or udp.dport != 53:
            return "", None
        return _ipv4(ip.src), bytes(udp.data) or None
    except Exception:
        return "", None


def _tools_map(spec: str) -> dict[str, str]:
    """`172.28.0.41=dnsexfiltrator,172.28.0.42=dns2tcp` -> dict."""
    out: dict[str, str] = {}
    for pair in spec.split(","):
        pair = pair.strip()
        if not pair:
            continue
        ip, _, tool = pair.partition("=")
        if not tool:
            raise SystemExit(f"--tools-map entry {pair!r} is not ip=tool")
        out[ip.strip()] = tool.strip()
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("pcap", type=Path)
    ap.add_argument("--out", type=Path, help="write NDJSON rows here (omit with --summary)")
    ap.add_argument("--tool", help="label traffic from this tool's lab address (dns2tcp | dnsexfiltrator)")
    ap.add_argument("--tools-map", default="", help="comma list of ip=tool, overrides --tool")
    ap.add_argument("--dataset", default="testbed", help="dataset column value")
    ap.add_argument("--throttle", default="", help="throttle column value, e.g. 5qps")
    ap.add_argument("--summary", action="store_true", help="print counts as JSON instead of rows")
    args = ap.parse_args(argv)

    tools = dict(LAB_IPS)
    if args.tool:
        # The default map covers both tools; --tool narrows which address is the tunnel.
        tools = {ip: (t if t == args.tool else "") for ip, t in LAB_IPS.items()}
        tools = {ip: t for ip, t in tools.items() if t}
    if args.tools_map:
        tools = _tools_map(args.tools_map)

    stats: dict[str, int] = {}
    rows = parse_pcap(args.pcap, tools, args.dataset, args.throttle, stats)
    if stats.get("truncated"):
        print(
            f"WARN {stats['truncated']} DNS frame(s) too short to parse (capture snaplen) - "
            "their qnames are lost, see the README before trusting counts from this pcap",
            file=sys.stderr,
        )

    if args.summary:
        by_tool: dict[str, int] = {}
        for r in rows:
            by_tool[r["tool"]] = by_tool.get(r["tool"], 0) + 1
        stats.setdefault("with_reply", sum(1 for r in rows if r["resp_size"]))
        print(json.dumps({"queries": len(rows), "by_tool": by_tool, **stats}))
        return 0

    if args.out is None:
        ap.error("--out is required unless --summary is given")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    print(f"wrote {len(rows)} rows to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
