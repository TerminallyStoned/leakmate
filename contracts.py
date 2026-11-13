from __future__ import annotations

import argparse
import ipaddress
import json
import math
import re
import sys
from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

TOOLS = ("benign", "iodine", "dnscat2", "dns2tcp", "dnsexfiltrator")
DATASETS = ("cic", "testbed", "synthetic")
EXPERIMENTS = ("E1", "E2", "E3", "E4", "E5", "S")
SPLITS = ("train", "test")
SESSION_GAP_S = 1800.0
TS_MIN, TS_MAX = 946_684_800.0, 4_102_444_800.0
QTYPE_NAMES: dict[int, str] = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 10: "NULL", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA",
    33: "SRV", 64: "SVCB", 65: "HTTPS", 255: "ANY",
}
QTYPE_RE = re.compile(r"^(UNKNOWN|TYPE\d+|[A-Z][A-Z0-9-]*)$")

REQUIRED_COLUMNS: dict[str, str] = {
    "ts": "float", "src_host": "str", "session_id": "str", "qname": "str", "qtype": "str",
    "resp_size": "int", "rcode": "int", "label": "int", "tool": "str", "dataset": "str", "throttle": "int",
}
OPTIONAL_COLUMNS: dict[str, str] = {"split": "str", "qname_truncated": "bool", "qlen_wire": "int", "source_file": "str"}
COLUMN_HINTS: dict[str, str] = {
    "ts": "query time in epoch seconds UTC (pcap timestamp)",
    "src_host": "IP address of the client that sent the query",
    "session_id": "set df['session_id'] = contracts.assign_sessions(df)",
    "qname": "query name as on the wire, no trailing dot",
    "qtype": "record type mnemonic; contracts.qtype_name(code) converts a numeric code",
    "resp_size": "DNS payload bytes of the response, 0 if no response was seen",
    "rcode": "response code 0-15, -1 if no response was seen",
    "label": "1 for tunnel queries, 0 for benign",
    "tool": f"one of {list(TOOLS)}",
    "dataset": f"one of {list(DATASETS)}",
    "throttle": "configured delay between tunnel queries in ms, 0 for benign or tool default",
}
DTYPE_FIX: dict[str, str] = {
    "float": "df['{c}'] = df['{c}'].astype('float64')",
    "int": "df['{c}'] = df['{c}'].astype('int64')",
    "str": "df['{c}'] = df['{c}'].astype(str)",
    "bool": "df['{c}'] = df['{c}'].astype(bool)",
}
REQUIRED_RESULT_KEYS: dict[str, str] = {
    "model": "str", "experiment": "str", "dataset": "list", "split": "str", "n_train": "int", "n_test": "int",
    "scores": "list", "labels": "list", "tools": "list", "src_hosts": "list", "train_time_s": "number",
    "latency_ms_per_query": "number", "score_meaning": "str", "config": "dict", "created_utc": "str",
}
OPTIONAL_RESULT_KEYS: dict[str, str] = {"session_ids": "list", "ts": "list"}
PER_ROW_KEYS = ("scores", "labels", "tools", "src_hosts", "session_ids", "ts")


class ContractError(ValueError):
    """A query table or results record that breaks docs/contracts.md."""

    def __init__(self, what: str, problems: list[str]) -> None:
        self.problems = problems
        lines = "\n".join(f"  - {p}" for p in problems)
        super().__init__(f"{what} breaks the contract in docs/contracts.md:\n{lines}")


def qtype_name(code: int | None) -> str:
    """Contract qtype string for a numeric QTYPE: mnemonic, TYPE<n> (RFC 3597) or UNKNOWN if lost."""
    if code is None:
        return "UNKNOWN"
    return QTYPE_NAMES.get(code, f"TYPE{code}")


def assign_sessions(df: pd.DataFrame, gap_s: float = SESSION_GAP_S) -> pd.Series:
    """Session ids '<capture>|<src_host>|<k>', where k grows after an idle gap longer than gap_s."""
    capture = df["source_file"] if "source_file" in df.columns else df["dataset"]
    key = capture.astype(str).to_numpy() + "|" + df["src_host"].astype(str).to_numpy()
    frame = pd.DataFrame({"key": key, "ts": df["ts"].to_numpy(dtype=np.float64)})
    frame = frame.sort_values(["key", "ts"], kind="stable")
    new_session = frame.groupby("key", sort=False)["ts"].diff() > gap_s
    k = new_session.astype(np.int64).groupby(frame["key"], sort=False).cumsum()
    sid = (frame["key"] + "|" + k.astype(str)).sort_index()
    return pd.Series(sid.to_numpy(), index=df.index, name="session_id")


def _examples(values: pd.Series | Sequence[Any], n: int = 3) -> str:
    """Up to n distinct example values for an error message."""
    seen: list[str] = []
    for v in values:
        r = repr(v)
        if r not in seen:
            seen.append(r)
        if len(seen) == n:
            break
    return ", ".join(seen)


def _dtype_ok(s: pd.Series, kind: str) -> bool:
    """Whether a column's dtype matches the contract kind."""
    if kind == "bool":
        return pd.api.types.is_bool_dtype(s)
    if pd.api.types.is_bool_dtype(s):
        return False
    if kind == "float":
        return pd.api.types.is_float_dtype(s)
    if kind == "int":
        return pd.api.types.is_integer_dtype(s)
    return pd.api.types.infer_dtype(s, skipna=True) in ("string", "empty")


def _bad(problems: list[str], col: str, mask: pd.Series, s: pd.Series, rule: str) -> None:
    """Append a problem if any row fails, with the count and example values."""
    n = int(mask.sum())
    if n:
        problems.append(f"column '{col}': {n} rows {rule} (e.g. {_examples(s[mask])})")


def validate_queries(df: pd.DataFrame) -> None:
    """Raise ContractError naming every column of a query table that breaks the contract."""
    problems: list[str] = []
    for c, kind in REQUIRED_COLUMNS.items():
        if c not in df.columns:
            problems.append(f"missing required column '{c}' ({kind}): {COLUMN_HINTS[c]}")
    ok: set[str] = set()
    for c, kind in {**REQUIRED_COLUMNS, **OPTIONAL_COLUMNS}.items():
        if c not in df.columns:
            continue
        s = df[c]
        nulls = int(s.isna().sum())
        if nulls:
            problems.append(f"column '{c}' has {nulls} null values; every row needs a value")
        elif not _dtype_ok(s, kind):
            problems.append(f"column '{c}' has dtype {s.dtype}, expected {kind}: {DTYPE_FIX[kind].format(c=c)}")
        else:
            ok.add(c)

    if "ts" in ok:
        ts = df["ts"]
        _bad(problems, "ts", ~np.isfinite(ts), ts, "are not finite")
        fin = ts[np.isfinite(ts)]
        if len(fin) and fin.max() > TS_MAX:
            problems.append("column 'ts' looks like milliseconds; store epoch seconds (divide by 1000)")
        else:
            _bad(problems, "ts", (ts < TS_MIN) | (ts > TS_MAX), ts, "are outside 2000-2100 in epoch seconds")
    if "src_host" in ok:
        bad_hosts = [h for h in df["src_host"].unique() if not _is_ip(str(h))]
        if bad_hosts:
            problems.append(f"column 'src_host': {len(bad_hosts)} values are not IP addresses "
                            f"(e.g. {_examples(bad_hosts)})")
    if "qname" in ok:
        q = df["qname"]
        _bad(problems, "qname", q.str.len() == 0, q, "are empty")
        _bad(problems, "qname", q.str.endswith("."), q, "end with '.'; strip the trailing dot")
    if "qtype" in ok:
        qt = df["qtype"]
        _bad(problems, "qtype", ~qt.str.fullmatch(QTYPE_RE.pattern), qt,
             "are not a mnemonic, TYPE<n> or UNKNOWN; use contracts.qtype_name(code)")
    if "resp_size" in ok:
        _bad(problems, "resp_size", df["resp_size"] < 0, df["resp_size"], "are negative; use 0 for no response")
    if "rcode" in ok:
        rc = df["rcode"]
        _bad(problems, "rcode", (rc < -1) | (rc > 15), rc, "are outside -1..15")
    if {"rcode", "resp_size"} <= ok:
        mism = (df["rcode"] == -1) != (df["resp_size"] == 0)
        _bad(problems, "rcode", mism, df["rcode"], "disagree with resp_size; no response means rcode -1 and resp_size 0")
    if "label" in ok:
        _bad(problems, "label", ~df["label"].isin([0, 1]), df["label"], "are not 0 or 1")
    if "tool" in ok:
        _bad(problems, "tool", ~df["tool"].isin(TOOLS), df["tool"], f"are not one of {list(TOOLS)}")
    if {"tool", "label"} <= ok:
        mism = (df["tool"] == "benign") != (df["label"] == 0)
        _bad(problems, "tool", mism, df["tool"], "disagree with label; tool is 'benign' exactly when label is 0")
    if "dataset" in ok:
        _bad(problems, "dataset", ~df["dataset"].isin(DATASETS), df["dataset"], f"are not one of {list(DATASETS)}")
    if "throttle" in ok:
        th = df["throttle"]
        _bad(problems, "throttle", th < 0, th, "are negative")
        if "label" in ok:
            _bad(problems, "throttle", (df["label"] == 0) & (th != 0), th, "are non-zero on benign rows")
    if "split" in ok:
        _bad(problems, "split", ~df["split"].isin(SPLITS), df["split"], f"are not one of {list(SPLITS)}")
    if "qlen_wire" in ok:
        _bad(problems, "qlen_wire", df["qlen_wire"] < 0, df["qlen_wire"], "are negative")
    capture = "source_file" if "source_file" in df.columns else "dataset"
    if {"session_id", "ts", "src_host", capture} <= ok:
        expected = assign_sessions(df)
        _bad(problems, "session_id", df["session_id"] != expected, df["session_id"],
             f"do not match '<{capture}>|<src_host>|<k>' with a new k after {SESSION_GAP_S:.0f} s idle; "
             "set df['session_id'] = contracts.assign_sessions(df)")
    if problems:
        raise ContractError("query table", problems)


def _is_ip(s: str) -> bool:
    """Whether s parses as an IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(s)
    except ValueError:
        return False
    return True


def _is_number(x: object) -> bool:
    """A real int or float, not a bool."""
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _type_ok(v: object, kind: str) -> bool:
    """Whether a results value matches the contract kind."""
    if kind == "int":
        return isinstance(v, int) and not isinstance(v, bool)
    if kind == "number":
        return _is_number(v)
    return isinstance(v, {"str": str, "list": list, "dict": dict}[kind])


def validate_results(res: Mapping[str, Any]) -> None:
    """Raise ContractError naming every key of a results record that breaks the contract."""
    problems: list[str] = []
    for k, kind in REQUIRED_RESULT_KEYS.items():
        if k not in res:
            problems.append(f"missing required key '{k}' ({kind})")
    ok: set[str] = set()
    for k, kind in {**REQUIRED_RESULT_KEYS, **OPTIONAL_RESULT_KEYS}.items():
        if k not in res:
            continue
        if _type_ok(res[k], kind):
            ok.add(k)
        else:
            problems.append(f"key '{k}' is {type(res[k]).__name__}, expected {kind}")

    if "experiment" in ok and res["experiment"] not in EXPERIMENTS:
        problems.append(f"key 'experiment' is {res['experiment']!r}, expected one of {list(EXPERIMENTS)}")
    if "dataset" in ok:
        bad = [d for d in res["dataset"] if d not in DATASETS]
        if bad or not res["dataset"]:
            problems.append(f"key 'dataset' must be a non-empty list drawn from {list(DATASETS)}, got {res['dataset']!r}")
    for k in ("n_train", "n_test", "train_time_s", "latency_ms_per_query"):
        if k in ok and res[k] < 0:
            problems.append(f"key '{k}' is negative")
    if "score_meaning" in ok and not res["score_meaning"].strip():
        problems.append("key 'score_meaning' is empty; say what the score is, higher = more suspicious")
    if "created_utc" in ok:
        try:
            when = datetime.fromisoformat(res["created_utc"])
        except ValueError:
            when = None
        if when is None or when.tzinfo is None:
            problems.append(f"key 'created_utc' is {res['created_utc']!r}; use "
                            "datetime.now(timezone.utc).isoformat(timespec='seconds')")
    n = res["n_test"] if "n_test" in ok else None
    for k in PER_ROW_KEYS:
        if k in ok and n is not None and len(res[k]) != n:
            problems.append(f"key '{k}' has {len(res[k])} entries but n_test is {n}; one entry per test row")
    if "scores" in ok:
        bad_s = [x for x in res["scores"] if not (_is_number(x) and math.isfinite(x))]
        if bad_s:
            problems.append(f"key 'scores': {len(bad_s)} entries are not finite numbers (e.g. {_examples(bad_s)}); "
                            "store raw scores, higher = more suspicious")
    if "labels" in ok:
        bad_l = [x for x in res["labels"] if x not in (0, 1) or isinstance(x, bool)]
        if bad_l:
            problems.append(f"key 'labels': {len(bad_l)} entries are not 0 or 1 (e.g. {_examples(bad_l)})")
    if "tools" in ok:
        bad_t = [x for x in res["tools"] if x not in TOOLS]
        if bad_t:
            problems.append(f"key 'tools': {len(bad_t)} entries are not one of {list(TOOLS)} (e.g. {_examples(bad_t)})")
        elif "labels" in ok and len(res["tools"]) == len(res["labels"]):
            mism = sum((t == "benign") != (y == 0) for t, y in zip(res["tools"], res["labels"]))
            if mism:
                problems.append(f"keys 'tools' and 'labels' disagree on {mism} rows; tool is 'benign' exactly "
                                "when label is 0")
    for k in ("src_hosts", "session_ids"):
        if k in ok:
            bad_h = [x for x in res[k] if not isinstance(x, str)]
            if bad_h:
                problems.append(f"key '{k}': {len(bad_h)} entries are not strings")
    if "ts" in ok:
        bad_ts = [x for x in res["ts"] if not (_is_number(x) and TS_MIN <= x <= TS_MAX)]
        if bad_ts:
            problems.append(f"key 'ts': {len(bad_ts)} entries are not epoch seconds (e.g. {_examples(bad_ts)})")
    if problems:
        raise ContractError("results record", problems)


def validate(obj: pd.DataFrame | Mapping[str, Any]) -> None:
    """Validate a query-table DataFrame or a results dict against docs/contracts.md."""
    if isinstance(obj, pd.DataFrame):
        validate_queries(obj)
    else:
        validate_results(obj)


def main(argv: Sequence[str] | None = None) -> int:
    """Validate .parquet query tables and .json results files given on the command line."""
    ap = argparse.ArgumentParser(description="Check query tables (.parquet) and results (.json) "
                                             "against docs/contracts.md")
    ap.add_argument("paths", nargs="+", type=Path)
    a = ap.parse_args(argv)
    failed = 0
    for p in a.paths:
        try:
            if p.suffix == ".parquet":
                validate_queries(pd.read_parquet(p))
            else:
                validate_results(json.loads(p.read_text()))
        except ContractError as e:
            failed += 1
            print(f"FAIL {p}\n{e}")
        else:
            print(f"ok   {p}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
