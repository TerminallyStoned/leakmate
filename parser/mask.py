"""Testbed query table with every registered domain replaced by one placeholder (an ablation).

    python -m parser.mask        # data/processed/testbed -> data/processed_nozone/testbed

Every lab tunnel name ends in the tool's zone under tunnel.test (testbed/attacker-ns/named.conf)
and no benign name does, so a model that reads the whole name can label a query from its
last labels alone. Here each name keeps its subdomain and swaps the registered domain for
MASK, the same for every row. The lab zones (d.tunnel.test, i.tunnel.test, ...) count as
registered domains, as if tunnel.test were a public suffix; dropping only the last two labels
would leave the tool's zone label (d, i, exfil, dns2tcp) as a new giveaway.

Run a model on the masked table with --data-root / --root data/processed_nozone (or --data)
and an ablation tag. The shared table stays as it is.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from contracts import validate_queries

LAB_ZONE = "tunnel.test"
MASK = "masked.domain"  # two labels, so a "last two labels = registered domain" rule still finds the subdomain


def mask_domain(qname: str) -> str:
    """'aGVsbG8.d.tunnel.test' -> 'aGVsbG8.masked.domain'; 'www.cloudflare.com' -> 'www.masked.domain'."""
    labels = qname.split(".")
    n = 3 if qname.lower().endswith("." + LAB_ZONE) else 2
    return ".".join([*labels[:-n], MASK])


def mask_table(df: pd.DataFrame) -> pd.DataFrame:
    out = df.assign(qname=df["qname"].map(mask_domain))
    validate_queries(out)
    return out


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="python -m parser.mask")
    ap.add_argument("--src", default="data/processed/testbed/queries.parquet")
    ap.add_argument("--out", default="data/processed_nozone/testbed/queries.parquet")
    a = ap.parse_args(argv)
    out = mask_table(pd.read_parquet(a.src))
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    out.to_parquet(a.out, index=False)
    print(f"-> {a.out}: {len(out)} rows, e.g.\n{out.groupby('tool').qname.first().to_string()}")


if __name__ == "__main__":
    main()
