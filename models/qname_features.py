"""Per-query features computed from a query-table row.

STOPGAP: the parser card (Yehan) owns the real M1 feature set in
`data/processed/<dataset>/features.parquet`. Until that exists, the Isolation
Forest baseline uses these. They follow the parser card's per-query list, so
switching later means passing `feature_cols` and the parser's table instead.
"""
from __future__ import annotations

import math
from collections import Counter

import numpy as np
import pandas as pd

QTYPE_CODES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "NULL": 10, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28,
               "SRV": 33, "HTTPS": 65, "ANY": 255}
FEATURE_COLS = ["q_len", "sub_len", "n_labels", "longest_label", "entropy", "sub_entropy", "n_digits", "n_upper",
                "n_special", "digit_ratio", "is_txt_null", "qtype_code", "resp_size"]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _row(q: str) -> list[float]:
    q = (q or "").rstrip(".")
    labels = [l for l in q.split(".") if l]
    # approximation of the registered domain: last two labels (parser will use a PSL)
    sub = ".".join(labels[:-2])
    return [len(q), len(sub), len(labels), max((len(l) for l in labels), default=0), _entropy(q), _entropy(sub),
            sum(c.isdigit() for c in q), sum(c.isupper() for c in q),
            sum(not (c.isalnum() or c == ".") for c in q), sum(c.isdigit() for c in q) / max(1, len(q))]


def compute(df: pd.DataFrame) -> pd.DataFrame:
    base = np.array([_row(str(q)) for q in df["qname"].fillna("")], dtype=np.float64).reshape(-1, 10)
    out = pd.DataFrame(base, columns=FEATURE_COLS[:10], index=df.index)
    qt = df["qtype"].astype(str).str.upper() if "qtype" in df else pd.Series("A", index=df.index)
    codes = qt.map(QTYPE_CODES)
    numeric = pd.to_numeric(qt, errors="coerce")  # qtype may already be numeric
    codes = codes.fillna(numeric).fillna(0)
    out["is_txt_null"] = codes.isin([10, 16]).astype(float)
    out["qtype_code"] = codes.astype(float)
    out["resp_size"] = pd.to_numeric(df["resp_size"], errors="coerce").fillna(0).astype(float) \
        if "resp_size" in df else 0.0
    return out
