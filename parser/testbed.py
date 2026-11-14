"""Testbed pcaps -> data/processed/testbed/queries.parquet, in the same schema as CIC.

    python -m parser testbed \\
        --capture data/raw/tools/dns2tcp_<utc>.pcap \\
        --capture data/raw/tools/dnsexfiltrator_<utc>.pcap@200 \\
        --capture data/raw/benign/resolver_<utc>.pcap \\
        --tools-map 172.28.0.45=iodine,172.28.0.46=dnscat2

Labels come from the sender's lab address (each tool client has a fixed IP in the compose
files), never from timestamps. Benign traffic comes from a capture at the resolver: the
generator's NDJSON sidecars leave resp_size empty for curl/apt/browser lookups, which would
make resp_size give the label away. The resolver's own forwarded queries are dropped so a
lookup is counted once.

`PCAP@MS` sets throttle (configured delay between tunnel queries, ms) for that capture's
tunnel rows; benign rows are always 0. Experiment 5 (low-and-slow) tests on
throttle > 0, so slow runs need it.
Split: per capture, first 70% of queries by time -> train, rest -> test.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from parser.pcap import finish, parse_pcap, with_split

RESOLVER = "172.28.0.2"
# Tool client addresses (testbed/tools/docker-compose.yml); add iodine/dnscat2 with --tools-map.
LAB_IPS = {"172.28.0.43": "dnsexfiltrator", "172.28.0.44": "dns2tcp"}


def build(captures: list[tuple[Path, int]], tools: dict[str, str], resolver: str = RESOLVER, train_frac: float = 0.7):
    """[(pcap, throttle_ms)] -> one validated query table; prints each capture's per-tool counts."""

    def tool_of(src: str, _qname: str) -> str | None:
        return None if src == resolver else tools.get(src, "benign")

    parts = []
    for path, throttle in captures:
        df = parse_pcap(Path(path), tool_of)
        if df.empty:  # e.g. captured behind the resolver: every sender is the resolver, so all were dropped
            raise SystemExit(f"{path}: no client DNS queries (queries sent by the resolver {resolver} are dropped)")
        df = with_split(df, train_frac)
        df["source_file"] = f"{Path(path).parent.name}/{Path(path).name}"  # <run id>/resolver.pcap stays unique
        df["throttle"] = df["label"] * throttle
        parts.append(df)
        print(f"{path}: {len(df)} queries, by tool {df.tool.value_counts().to_dict()}, throttle {throttle} ms")
    return finish(parts, "testbed")


def _capture(spec: str) -> tuple[Path, int]:
    path, sep, ms = spec.rpartition("@")
    if not sep:
        return Path(spec), 0
    if not ms.isdigit():
        raise argparse.ArgumentTypeError(f"{spec!r}: expected PCAP or PCAP@<throttle ms>")
    return Path(path), int(ms)


def _tools_map(spec: str) -> dict[str, str]:
    pairs = [p.split("=", 1) for p in spec.split(",") if p.strip()]
    if any(len(p) != 2 for p in pairs):
        raise argparse.ArgumentTypeError(f"{spec!r}: expected ip=tool,ip=tool")
    return {ip.strip(): tool.strip() for ip, tool in pairs}


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="python -m parser testbed")
    ap.add_argument("--capture", type=_capture, action="append", required=True, help="PCAP or PCAP@<throttle ms>")
    ap.add_argument("--tools-map", type=_tools_map, default={}, help="extra client ip=tool pairs")
    ap.add_argument("--resolver", default=RESOLVER, help="resolver address; its forwarded queries are dropped")
    ap.add_argument("--out", default="data/processed/testbed/queries.parquet")
    a = ap.parse_args(argv)
    out = build(a.capture, {**LAB_IPS, **a.tools_map}, a.resolver)
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    out.to_parquet(a.out, index=False)
    by = {k: out.groupby([k, "split"]).size().unstack(fill_value=0).to_string() for k in ("tool", "label")}
    print(f"-> {a.out}: {len(out)} rows\n\nper tool:\n{by['tool']}\n\nper class (label):\n{by['label']}")
