"""SYNTHETIC query table in the contract schema, for testing M2 code only.

Not real data and never used for results. Stand-in until Yehan's
1,000-row CIC sample file lands. Benign names come from Tranco plus common
subdomains; "tunnel" names are base32/hex/base64 payloads under an attacker
domain, mimicking the tools' encodings.

  python scripts/make_synthetic_sample.py --tranco data/external/tranco.csv \
      --n 20000 --out data/sample/synthetic_queries.parquet
"""
import argparse
import base64
import os
import random
from pathlib import Path

import pandas as pd

SUBS = ["www", "api", "cdn", "mail", "m", "static", "img", "login", "app", "assets", "edge", "s3", "auth", ""]


def tunnel_name(tool: str, rnd: random.Random) -> tuple[str, str]:
    payload = os.urandom(rnd.randint(10, 60))
    if tool == "iodine":
        enc = base64.b32encode(payload).decode().rstrip("=").lower(); dom, qt = "t.evil-tun.net", "NULL"
    elif tool == "dnscat2":
        enc = payload.hex(); dom, qt = "c2.badcat.org", "TXT"
    elif tool == "dns2tcp":
        enc = base64.b64encode(payload).decode().rstrip("=").replace("+", "-").replace("/", "_"); dom, qt = "x.d2t.io", "TXT"
    else:  # dnsexfiltrator
        enc = base64.b32encode(payload).decode().rstrip("="); dom, qt = "exf.data-sink.com", "A"
    labels = [enc[i:i + 63] for i in range(0, len(enc), 63)]
    return ".".join(labels + [dom]), qt


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tranco", required=True)
    ap.add_argument("--n", type=int, default=20000)
    ap.add_argument("--tunnel-frac", type=float, default=0.1)
    ap.add_argument("--out", default="data/sample/synthetic_queries.parquet")
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args()
    rnd = random.Random(a.seed)
    doms = pd.read_csv(a.tranco, header=None, names=["r", "d"], nrows=50000)["d"].tolist()
    rows, t = [], 1_700_000_000.0
    tools = ["iodine", "dnscat2", "dns2tcp", "dnsexfiltrator"]
    for _ in range(a.n):
        t += rnd.expovariate(5)
        if rnd.random() < a.tunnel_frac:
            tool = rnd.choice(tools); q, qt = tunnel_name(tool, rnd); lab = 1
            host, sess = f"10.0.0.{tools.index(tool) + 50}", f"{tool}-{int(t // 600)}"
        else:
            tool, lab, sub = "benign", 0, rnd.choice(SUBS)
            d = doms[min(int(rnd.paretovariate(1.1)) - 1, len(doms) - 1)] if rnd.random() < .7 else rnd.choice(doms)
            q, qt = (f"{sub}.{d}" if sub else d), rnd.choice(["A", "A", "A", "AAAA", "HTTPS", "CNAME"])
            host, sess = f"10.0.0.{rnd.randint(2, 40)}", f"benign-{int(t // 600)}"
        rows.append(dict(ts=t, src_host=host, session_id=sess, qname=q, qtype=qt,
                         resp_size=rnd.randint(40, 512), rcode=0, label=lab, tool=tool,
                         dataset="synthetic", throttle=0))
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_parquet(a.out, index=False)
    print(f"wrote {len(rows)} rows -> {a.out}")


if __name__ == "__main__":
    main()
