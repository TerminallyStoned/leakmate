from __future__ import annotations

import argparse
import base64
import random
import sys
from pathlib import Path
from typing import Any

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from contracts import assign_sessions, validate_queries  # noqa: E402

SUBS = ["www", "api", "cdn", "mail", "m", "static", "img", "login", "app", "assets", "edge", "s3", "auth", ""]
BUILTIN_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "microsoft.com", "apple.com", "amazon.com", "wikipedia.org",
    "github.com", "cloudflare.com", "netflix.com", "linkedin.com", "yahoo.com", "bing.com", "office.com",
    "zoom.us", "slack.com", "reddit.com", "instagram.com", "whatsapp.net", "akamaiedge.net", "gstatic.com",
    "googleapis.com", "windowsupdate.com", "ubuntu.com", "debian.org", "python.org", "pypi.org", "nus.edu.sg",
    "singaporetech.edu.sg", "gov.sg",
]
TOOLS = ["iodine", "dnscat2", "dns2tcp", "dnsexfiltrator"]
SOURCE_FILE = "synthetic/sample.pcap"


def tunnel_name(tool: str, rnd: random.Random) -> tuple[str, str]:
    """A tunnel-like query name and qtype mimicking the tool's encoding."""
    payload = rnd.randbytes(rnd.randint(10, 60))
    if tool == "iodine":
        enc, dom, qt = base64.b32encode(payload).decode().rstrip("=").lower(), "t.evil-tun.net", "NULL"
    elif tool == "dnscat2":
        enc, dom, qt = payload.hex(), "c2.badcat.org", "TXT"
    elif tool == "dns2tcp":
        b64 = base64.b64encode(payload).decode().rstrip("=")
        enc, dom, qt = b64.replace("+", "-").replace("/", "_"), "x.d2t.io", "TXT"
    else:
        enc, dom, qt = base64.b32encode(payload).decode().rstrip("="), "exf.data-sink.com", "A"
    labels = [enc[i:i + 63] for i in range(0, len(enc), 63)]
    return ".".join([*labels, dom]), qt


def make_sample(n: int = 1000, tunnel_frac: float = 0.1, seed: int = 0, domains: list[str] | None = None,
                train_frac: float = 0.7) -> pd.DataFrame:
    """A schema-valid synthetic query table of n rows (testing only, never results)."""
    rnd = random.Random(seed)
    doms = domains or BUILTIN_DOMAINS
    rows: list[dict[str, Any]] = []
    t = 1_700_000_000.0
    for _ in range(n):
        t += rnd.expovariate(5)
        if rnd.random() < tunnel_frac:
            tool = rnd.choice(TOOLS)
            q, qt = tunnel_name(tool, rnd)
            host, lab = f"10.0.0.{TOOLS.index(tool) + 50}", 1
        else:
            tool, lab, sub = "benign", 0, rnd.choice(SUBS)
            d = doms[min(int(rnd.paretovariate(1.1)) - 1, len(doms) - 1)] if rnd.random() < 0.7 else rnd.choice(doms)
            q, qt = (f"{sub}.{d}" if sub else d), rnd.choice(["A", "A", "A", "AAAA", "HTTPS", "CNAME"])
            host = f"10.0.0.{rnd.randint(2, 40)}"
        answered = rnd.random() > 0.02
        rows.append(dict(ts=t, src_host=host, qname=q, qtype=qt,
                         resp_size=rnd.randint(40, 512) if answered else 0,
                         rcode=(3 if rnd.random() < 0.05 else 0) if answered else -1,
                         label=lab, tool=tool, dataset="synthetic", throttle=0,
                         qname_truncated=False, qlen_wire=len(q) + 18, source_file=SOURCE_FILE))
    df = pd.DataFrame(rows)
    df["session_id"] = assign_sessions(df)
    df["split"] = ["train" if i < int(n * train_frac) else "test" for i in range(n)]
    return df


def main(argv: list[str] | None = None) -> None:
    """Write a synthetic query table in the contract schema (docs/contracts.md)."""
    ap = argparse.ArgumentParser(description="Synthetic query table for testing code, never for results")
    ap.add_argument("--tranco", help="Tranco CSV for benign names; a built-in list is used if omitted")
    ap.add_argument("--n", type=int, default=1000)
    ap.add_argument("--tunnel-frac", type=float, default=0.1)
    ap.add_argument("--out", default="data/sample/synthetic_queries.parquet")
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args(argv)
    doms = None
    if a.tranco:
        doms = pd.read_csv(a.tranco, header=None, names=["r", "d"], nrows=50000)["d"].astype(str).tolist()
    df = make_sample(a.n, a.tunnel_frac, a.seed, doms)
    validate_queries(df)
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(a.out, index=False)
    print(f"wrote {len(df)} schema-valid rows -> {a.out}")


if __name__ == "__main__":
    main()
