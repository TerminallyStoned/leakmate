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

CIC_BENIGN, CIC_LIGHT, CIC_HEAVY = 641_642, 53_978, 323_698
TUNNEL_FRAC = (CIC_LIGHT + CIC_HEAVY) / (CIC_BENIGN + CIC_LIGHT + CIC_HEAVY)
TRAIN_FRAC = 0.7
BENIGN_QTYPES = {"A": 61.5, "PTR": 27.2, "MX": 5.2, "ANY": 4.6}
NO_ANSWER_FRAC, NEGATIVE_FRAC = 0.23, 0.13
ZIPF_ALPHA_SLD = 1.11378
DNS_HEADER, QUESTION_FIXED, RR_FIXED, POINTER = 12, 4, 10, 2
MAX_NAME_WIRE, MAX_LABEL = 255, 63
TUNNEL_DOMAIN = "tunnel.test"
TOOLS = ["iodine", "dnscat2", "dns2tcp", "dnsexfiltrator"]
SOURCE_FILE = "synthetic/sample.pcap"
START_TS = 1_700_000_000.0
QUERIES_PER_S = 5.0
N_BENIGN_HOSTS = 39
FALLBACK_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "microsoft.com", "apple.com", "amazon.com", "wikipedia.org",
    "github.com", "cloudflare.com", "netflix.com", "linkedin.com", "yahoo.com", "bing.com", "office.com",
    "zoom.us", "slack.com", "reddit.com", "instagram.com", "whatsapp.net", "akamaiedge.net", "gstatic.com",
    "googleapis.com", "windowsupdate.com", "ubuntu.com", "debian.org", "python.org", "pypi.org", "nus.edu.sg",
    "singaporetech.edu.sg", "gov.sg",
]


def wire_len(name: str) -> int:
    """Octets a name takes on the wire: one length byte per label plus the root byte (RFC 1035 3.1)."""
    return len(name) + 2


def split_labels(s: str, size: int) -> list[str]:
    """Cut an encoded string into labels of at most size characters."""
    return [s[i : i + size] for i in range(0, len(s), size)]


def fill_name(enc: str, max_text: int, suffix: str) -> str:
    """The longest '<63-character labels of enc>.<suffix>' of at most max_text characters."""
    for n in range(len(enc), 0, -1):
        name = ".".join([*split_labels(enc[:n], MAX_LABEL), suffix])
        if len(name) <= max_text:
            return name
    raise ValueError("suffix leaves no room for data")


def make_sample(
    n: int = 1000,
    tunnel_frac: float = TUNNEL_FRAC,
    seed: int = 0,
    domains: list[str] | None = None,
    train_frac: float = TRAIN_FRAC,
) -> pd.DataFrame:
    """A schema-valid synthetic query table of n rows (testing only, never results)."""
    rnd = random.Random(seed)
    doms = domains or FALLBACK_DOMAINS
    weights = [1.0 / r**ZIPF_ALPHA_SLD for r in range(1, len(doms) + 1)]
    qtypes, qweights = list(BENIGN_QTYPES), list(BENIGN_QTYPES.values())
    chunks = dict.fromkeys(TOOLS, 0)
    rows: list[dict[str, Any]] = []
    t = START_TS
    for _ in range(n):
        t += rnd.expovariate(QUERIES_PER_S)
        if rnd.random() < tunnel_frac:
            tool, dom = rnd.choice(TOOLS), TUNNEL_DOMAIN
            if tool == "iodine":
                enc = base64.b32encode(rnd.randbytes(MAX_NAME_WIRE)).decode().rstrip("=").lower()
                q, qt = fill_name(enc, MAX_NAME_WIRE - 2, dom), "NULL"
            elif tool == "dnscat2":
                data_bytes = MAX_NAME_WIRE // 2 - len(dom) - 1 - (MAX_NAME_WIRE // 62 + 1)
                q = ".".join([*split_labels(rnd.randbytes(data_bytes).hex(), 60), dom])
                qt = rnd.choice(["TXT", "CNAME", "MX"])
            elif tool == "dns2tcp":
                enc = base64.b64encode(rnd.randbytes(200)).decode().rstrip("=")
                q, qt = fill_name(enc, 200 - 2, dom), "TXT"
            else:
                bytes_left = 255 - 10 - (len(dom) + 2)
                chunk_max = (bytes_left // (MAX_LABEL + 1)) * MAX_LABEL + bytes_left % (MAX_LABEL + 1) - 1
                data = base64.urlsafe_b64encode(rnd.randbytes(chunk_max)).decode().rstrip("=")[:chunk_max]
                q, qt = ".".join([str(chunks[tool]), *split_labels(data, MAX_LABEL), dom]), "TXT"
            chunks[tool] += 1
            host, lab, rcode = f"10.0.0.{TOOLS.index(tool) + 50}", 1, 0
        else:
            tool, lab = "benign", 0
            host = f"10.0.0.{rnd.randint(2, N_BENIGN_HOSTS + 1)}"
            qt = rnd.choices(qtypes, qweights)[0]
            if qt == "PTR":
                q = f"{rnd.randint(1, 254)}.{rnd.randint(0, 255)}.{rnd.randint(0, 255)}.10.in-addr.arpa"
            else:
                q = rnd.choices(doms, weights)[0]
            u = rnd.random()
            rcode = -1 if u < NO_ANSWER_FRAC else 3 if u < NO_ANSWER_FRAC + NEGATIVE_FRAC else 0
        qlen = DNS_HEADER + wire_len(q) + QUESTION_FIXED
        if rcode == -1:
            resp = 0
        elif rcode == 0:
            if qt in ("PTR", "CNAME", "MX"):
                rdata = wire_len(rnd.choice(doms)) + (2 if qt == "MX" else 0)
            else:
                rdata = {"A": 4, "ANY": 4, "AAAA": 16, "TXT": 1, "NULL": 0}[qt]
            resp = qlen + POINTER + RR_FIXED + rdata
        else:
            resp = qlen
        rows.append(
            dict(
                ts=t,
                src_host=host,
                qname=q,
                qtype=qt,
                resp_size=resp,
                rcode=rcode,
                label=lab,
                tool=tool,
                dataset="synthetic",
                throttle=0,
                qname_truncated=False,
                qlen_wire=qlen,
                source_file=SOURCE_FILE,
            )
        )
    df = pd.DataFrame(rows)
    df["session_id"] = assign_sessions(df)
    df["split"] = ["train" if i < int(n * train_frac) else "test" for i in range(n)]
    return df


def main(argv: list[str] | None = None) -> None:
    """Write a synthetic query table in the contract schema (docs/contracts.md)."""
    ap = argparse.ArgumentParser(description="Synthetic query table for testing code, never for results")
    ap.add_argument("--tranco", help="Tranco CSV (rank,domain) for ranked benign names; a fallback list is used if omitted")
    ap.add_argument("--n", type=int, default=1000)
    ap.add_argument("--tunnel-frac", type=float, default=TUNNEL_FRAC)
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
