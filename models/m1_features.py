"""Feature matrix for M1 (XGBoost) and its Random Forest baseline.

One place decides which columns the supervised models see, so M1 and the RF
baseline are always compared on identical inputs.

  per-query   models.qname_features (stopgap until the parser's feature table)
  wire size   `qlen_wire`: the true query size in bytes. Taken from the table
              when present (CIC extractor), otherwise estimated from the name
              as len(qname) + 18 (12 B header + 2 B name framing + 4 B qtype/qclass,
              no EDNS), so a model trained on CIC can still score testbed tables.
  per-host    models.host_features (past-only sliding window). Window key is
              "<source_file>|<src_host>" when the table has source_file, so two
              captures that reuse an IP never share a window.

CIC LEAKAGE GUARD
The CIC pcaps were captured with snaplen = 96 B (docs/m2.md): exfil query names
are cut to ~40 chars, lose their qtype and lose their attacker domain. Some
features then describe where the capture cut the packet instead of what the
tunnel did, and a supervised model will happily learn that artefact. When the
table has a `qname_truncated` column (scripts/cic_to_queries.py output), these
groups are dropped unless cfg["keep_cic_leaky"] is True (ablation only):

  qtype          qtype_code, is_txt_null, h_txt_null_ratio
                 qtype sits after the name, so it is missing on truncated rows.
  capped_length  q_len, sub_len, longest_label, h_len_mean
                 lengths pile up at the ~40-char cut; qlen_wire keeps the true size.
  lost_domain    n_labels, sub_entropy, h_parent_uniq
                 with the domain cut off, "<n>.<data>" looks like a bare 2-label
                 domain: n_labels is always 2, the subdomain is empty (entropy 0)
                 and every name is its own parent, which inverts the real signal.

Kept on CIC: entropy, n_digits, n_upper, n_special, digit_ratio, resp_size,
qlen_wire, h_qpm, h_uniq_ratio, h_ent_mean, h_ent_std.
"""
from __future__ import annotations

import pandas as pd

from models import host_features, qname_features

CIC_LEAKY_GROUPS = {
    "qtype": ["qtype_code", "is_txt_null", "h_txt_null_ratio"],
    "capped_length": ["q_len", "sub_len", "longest_label", "h_len_mean"],
    "lost_domain": ["n_labels", "sub_entropy", "h_parent_uniq"],
}
CIC_LEAKY = [c for cols in CIC_LEAKY_GROUPS.values() for c in cols]

DEFAULT_CFG = {"feature_cols": None, "host": True, "window_s": 60.0, "drop_cols": [], "keep_cic_leaky": False}

# Precomputed feature columns carry this prefix. m1_run computes features once on
# the whole table (so a host window can reach back across the train/test cut,
# past-only) and attaches them; train/score then use them as-is.
PREFIX = "f_"
WIRE_OVERHEAD = 18  # DNS header 12 + name length/terminator 2 + qtype/qclass 4


def is_cic_table(df: pd.DataFrame) -> bool:
    return "qname_truncated" in df.columns


def host_key(df: pd.DataFrame) -> pd.Series:
    """Window key per row: source_file|src_host if the table has source_file, else src_host."""
    host = df["src_host"].fillna("").astype(str)
    if "source_file" in df.columns:
        return df["source_file"].fillna("").astype(str) + "|" + host
    return host


def qlen_wire(df: pd.DataFrame) -> pd.Series:
    """True query size from the table, or an estimate from the name where it is missing."""
    est = df["qname"].fillna("").astype(str).str.rstrip(".").str.len().astype(float) + WIRE_OVERHEAD
    if "qlen_wire" in df.columns:
        return pd.to_numeric(df["qlen_wire"], errors="coerce").fillna(est).astype(float)
    return est


def build(df: pd.DataFrame, cfg: dict | None = None) -> pd.DataFrame:
    """Return the full feature frame (before any drops) for df, same index."""
    cfg = {**DEFAULT_CFG, **(cfg or {})}
    cols = cfg["feature_cols"]
    if cols and all(c in df.columns for c in cols):  # parser features, once they exist
        return df[cols].astype(float)
    X = qname_features.compute(df)
    X["qlen_wire"] = qlen_wire(df)
    if cfg["host"] and {"ts", "src_host"} <= set(df.columns):
        X = X.join(host_features.compute(df, cfg["window_s"], key=host_key(df)))
    return X


def attach(df: pd.DataFrame, cfg: dict | None = None) -> pd.DataFrame:
    """df plus its features as PREFIX-ed columns."""
    return df.join(build(df, cfg).add_prefix(PREFIX))


def features_for(df: pd.DataFrame, cfg: dict | None = None) -> pd.DataFrame:
    """Precomputed PREFIX-ed columns if df has them, else build them now."""
    pre = [c for c in df.columns if c.startswith(PREFIX)]
    if pre:
        return df[pre].rename(columns=lambda c: c[len(PREFIX):]).astype(float)
    return build(df, cfg)


def drop_list(df: pd.DataFrame, cfg: dict | None = None) -> list[str]:
    """Columns to remove for this table and config.

    cfg["keep_cic_leaky"]: False (default, drop every CIC_LEAKY_GROUPS column),
    True (keep them all), or a list of group names to keep (per-artefact ablation)."""
    cfg = {**DEFAULT_CFG, **(cfg or {})}
    drop = list(cfg["drop_cols"])
    if not cfg["host"]:
        drop += host_features.HOST_COLS
    keep = cfg["keep_cic_leaky"]
    if is_cic_table(df) and keep is not True:
        keep_groups = set(keep or [])
        unknown = keep_groups - set(CIC_LEAKY_GROUPS)
        if unknown:
            raise ValueError(f"unknown CIC leaky group(s) {sorted(unknown)}; choose from {sorted(CIC_LEAKY_GROUPS)}")
        for group, cols in CIC_LEAKY_GROUPS.items():
            if group not in keep_groups:
                drop += cols
    return sorted(set(drop))


def select(X: pd.DataFrame, cols: list[str]) -> pd.DataFrame:
    """Columns `cols` of X in that order; any column the model expects but X lacks is 0."""
    return X.reindex(columns=cols, fill_value=0.0).astype(float)
