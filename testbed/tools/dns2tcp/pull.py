#!/usr/bin/env python3
"""Download a file through the tunnel at an exact bytes/second.

`curl --limit-rate` cannot be used here: it rounds to 1k and rejects anything below 10k,
while the card's --rate is in bytes/second and small rates are the interesting case
(low-and-slow is experiment E5). Sleeping per read is precise enough at these sizes.

Usage: pull.py <bytes-per-second> <local-port> <expected-bytes> [path]
The tunnel's local port is 127.0.0.1:8081 on the client container (dns2tcpc -l 8081),
which speaks plain HTTP to the resource dns2tcpd forwards (127.0.0.1:8080, a static
file server inside the server container).
"""

from __future__ import annotations

import sys
import time
import urllib.request


def main() -> int:
    rate, port, want = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
    dest = sys.argv[4] if len(sys.argv) > 4 else "/tmp/got.bin"

    # One read per quarter of the rate window keeps the pacer from overshooting at low
    # rates, where a 4096-byte read would otherwise be a whole second of budget.
    step = max(64, rate // 4)
    buf = bytearray()
    start = time.monotonic()
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/blob.bin", timeout=120) as resp:
        while chunk := resp.read(step):
            buf += chunk
            # Pace on bytes delivered, not on wall-clock sleeps, so the average holds.
            lag = len(buf) / rate - (time.monotonic() - start)
            if lag > 0:
                time.sleep(lag)

    with open(dest, "wb") as fh:
        fh.write(buf)
    elapsed = time.monotonic() - start
    print(f"pulled {len(buf)} bytes in {elapsed:.1f}s ({len(buf) / max(elapsed, 1e-9):.0f} B/s)")
    if len(buf) != want:
        print(f"FAIL tunnel delivered {len(buf)} of {want} bytes", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
