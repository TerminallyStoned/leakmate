"""Frame sources for the live sniffer: a network interface (Scapy) or a pcap file replayed.

Both yield (timestamp, frame). The frame is the raw Ethernet frame, decoded later by the same code that
reads capture files (parser.pcap.dns_packet), so Scapy is only used to take packets off the wire.
"""

from __future__ import annotations

import queue
import time
from collections.abc import Iterator
from pathlib import Path

from parser.pcap import frames

BPF = "udp port 53"


def pcap_frames(path: str | Path, speed: float = 0.0) -> Iterator[tuple[float, bytes]]:
    """Replay a capture file. speed 0 = as fast as possible; 1 = at the recorded pace; 10 = ten times faster."""
    first = wall = None
    for ts, buf in frames(Path(path)):
        ts = float(ts)
        if speed > 0:
            if first is None:
                first, wall = ts, time.monotonic()
            delay = (ts - first) / speed - (time.monotonic() - wall)
            if delay > 0:
                time.sleep(delay)
        yield ts, buf


def find_interface(spec: str) -> str:
    """`eth0` -> eth0. `ip:172.28.0.2` -> the interface that holds that address.

    The testbed resolver has a lab and an upstream interface and either can be eth0, so name it by address."""
    if not spec.startswith("ip:"):
        return spec
    from scapy.all import get_if_addr, get_if_list  # needs requirements-live.txt

    want = spec[3:]
    for name in get_if_list():
        if get_if_addr(name) == want:
            return name
    raise SystemExit(f"no interface holds {want} (interfaces here: {', '.join(get_if_list())})")


def sniff_frames(iface: str, tick_s: float = 0.25, bpf: str = BPF) -> Iterator[tuple[float, bytes | None]]:
    """Sniff DNS on an interface until interrupted. Needs root (or CAP_NET_RAW) and Scapy.

    While no packet arrives it yields (now, None) every tick_s seconds, so the pipeline's clock keeps moving."""
    from scapy.all import AsyncSniffer  # needs requirements-live.txt

    inbox: queue.Queue = queue.Queue()
    sniffer = AsyncSniffer(iface=iface, filter=bpf, prn=inbox.put, store=False)
    sniffer.start()
    try:
        while True:
            try:
                pkt = inbox.get(timeout=tick_s)
            except queue.Empty:
                yield time.time(), None
            else:
                yield float(pkt.time), bytes(pkt)
    finally:
        if sniffer.running:
            sniffer.stop()
