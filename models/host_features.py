"""Per-host sliding-window features (past-only) for M1.

STOPGAP, like models/qname_features.py: the parser card owns the real per-host
features. Until those land, M1 computes these. Each row gets statistics of the
queries the SAME source host sent in the window (t - window_s, t], including the
row itself and never anything later, so a live detector could compute the same
values and no future information leaks into training.

Columns
  h_qpm             queries from this host in the window, scaled to per minute
  h_uniq_ratio      distinct qnames / queries in the window (tunnels ~ 1.0)
  h_parent_uniq     distinct qnames under this row's parent domain in the window
  h_ent_mean        mean Shannon entropy of the window's qnames
  h_ent_std         std of that entropy
  h_len_mean        mean qname length in the window
  h_txt_null_ratio  share of TXT/NULL queries in the window

`parent` is approximated as the last two labels (the parser will use a public
suffix list). On CIC, truncated exfil names lose their attacker domain, so
h_parent_uniq is distorted there (m1_features drops it on CIC); h_uniq_ratio
does not depend on the parent.

Window key: by default the source host. Pass `key` (one value per row) to
group differently; m1_features uses "<source_file>|<src_host>" when the table
has a source_file column, so separate captures that reuse an IP address (CIC's
benign and attack pcaps) never share a window.
"""
from __future__ import annotations

from collections import Counter, deque

import numpy as np
import pandas as pd

from models.qname_features import QTYPE_CODES, _entropy

HOST_COLS = ["h_qpm", "h_uniq_ratio", "h_parent_uniq", "h_ent_mean", "h_ent_std", "h_len_mean",
             "h_txt_null_ratio"]


def _parent(q: str) -> str:
    labels = [l for l in q.rstrip(".").split(".") if l]
    return ".".join(labels[-2:])


def _is_txt_null(qtype) -> bool:
    s = str(qtype).upper()
    code = QTYPE_CODES.get(s)
    if code is None:
        try:
            code = int(float(s))
        except ValueError:
            code = 0
    return code in (10, 16)


def compute(df: pd.DataFrame, window_s: float = 60.0, key: pd.Series | None = None) -> pd.DataFrame:
    """Return HOST_COLS for every row of df (same index). Needs ts, src_host, qname.

    key: optional per-row window key (default: src_host)."""
    out = np.zeros((len(df), len(HOST_COLS)), dtype=np.float64)
    if len(df) == 0:
        return pd.DataFrame(out, columns=HOST_COLS, index=df.index)

    qnames = df["qname"].fillna("").astype(str).str.rstrip(".").to_numpy()
    ts = pd.to_numeric(df["ts"], errors="coerce").fillna(0.0).to_numpy(dtype=np.float64)
    hosts = (key if key is not None else df["src_host"]).fillna("").astype(str).to_numpy()
    qtypes = df["qtype"].to_numpy() if "qtype" in df else np.array(["A"] * len(df), dtype=object)

    # per-row values used by the window statistics
    ent = np.array([_entropy(q) for q in qnames], dtype=np.float64)
    qlen = np.array([len(q) for q in qnames], dtype=np.float64)
    tn = np.array([_is_txt_null(t) for t in qtypes], dtype=np.float64)
    parents = [_parent(q) for q in qnames]

    # stable order: by host, then time, then original position (ties keep row order)
    order = np.lexsort((np.arange(len(df)), ts, hosts))
    minutes = window_s / 60.0

    cur_host = None
    for i in order:
        h = hosts[i]
        if h != cur_host:  # reset window state for a new host
            cur_host = h
            win = deque()
            q_count, par_count = Counter(), {}
            s_ent = s_ent2 = s_len = s_tn = 0.0
        # add row i
        win.append(i)
        q_count[qnames[i]] += 1
        par_count.setdefault(parents[i], Counter())[qnames[i]] += 1
        s_ent += ent[i]; s_ent2 += ent[i] * ent[i]; s_len += qlen[i]; s_tn += tn[i]
        # evict rows that fell out of (t - window_s, t]
        while win and ts[win[0]] <= ts[i] - window_s:
            j = win.popleft()
            q_count[qnames[j]] -= 1
            if q_count[qnames[j]] == 0:
                del q_count[qnames[j]]
            pc = par_count[parents[j]]
            pc[qnames[j]] -= 1
            if pc[qnames[j]] == 0:
                del pc[qnames[j]]
            if not pc:
                del par_count[parents[j]]
            s_ent -= ent[j]; s_ent2 -= ent[j] * ent[j]; s_len -= qlen[j]; s_tn -= tn[j]
        n = len(win)
        mean_e = s_ent / n
        out[i] = [n / minutes, len(q_count) / n, len(par_count.get(parents[i], ())), mean_e,
                  float(np.sqrt(max(s_ent2 / n - mean_e * mean_e, 0.0))), s_len / n, s_tn / n]
    return pd.DataFrame(out, columns=HOST_COLS, index=df.index)
