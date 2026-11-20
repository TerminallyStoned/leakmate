"""Two well-known outside detectors on the Experiment 1 test rows: Splunk's pretrained model and RITA.

Neither is trained on our data. Each writes results_external/<tool>/E1.json in the shared results
format, with rows in the same order as results/<model>/E1.json, so `python -m eval.summarise
--results-dir results_external` scores them like our models. Steps and findings: docs/external-baselines.md.

    python scripts/external_baselines.py zeek-list --out work/zeek/zeek_list.tsv
    #   ... run Zeek on those pcaps (scripts/external/zeek_run.sh), then:
    python scripts/external_baselines.py zeek-test-only --zeek work/zeek --out work/zeek_test
    #   ... run RITA on work/zeek_test (scripts/external/rita-compose.yml), export its CSV, then:
    python scripts/external_baselines.py rita --csv work/rita_e1.csv
    python scripts/external_baselines.py splunk --weights <path to the .pt in Splunk's tar.gz>
"""

from __future__ import annotations

import argparse
import json
import math
import string
import sys
import time
from collections import Counter, defaultdict, deque
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from contracts import validate_results  # noqa: E402
from eval.experiments import DATA_ROOT, get_split  # noqa: E402

RITA_SEVERITY = {"Low": 0.25, "Medium": 0.5, "High": 0.75, "Critical": 1.0}


def test_rows(root: Path) -> pd.DataFrame:
    return get_split("E1", root)[1].reset_index(drop=True)


def write(
    out_dir: Path, model: str, te: pd.DataFrame, scores, threshold: float, meaning: str, latency_ms: float, config: dict
):
    res = {
        "model": model,
        "experiment": "E1",
        "dataset": ["testbed"],
        "split": "split_column",
        "n_train": 0,
        "n_test": len(te),
        "scores": [float(s) for s in scores],
        "labels": te["label"].astype(int).tolist(),
        "tools": te["tool"].astype(str).tolist(),
        "src_hosts": te["src_host"].astype(str).tolist(),
        "session_ids": te["session_id"].astype(str).tolist(),
        "ts": te["ts"].astype(float).tolist(),
        "train_time_s": 0.0,
        "latency_ms_per_query": float(latency_ms),
        "score_meaning": meaning,
        "threshold": threshold,
        "config": {"pretrained": True, "trained_on_this_data": False, **config},
        "created_utc": datetime.now(UTC).isoformat(timespec="seconds"),
    }
    validate_results(res)
    path = out_dir / model / "E1.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(res))
    print(f"wrote {path}")


# ---- Zeek input for RITA ---------------------------------------------------------------------


def zeek_list(a):
    """The pcaps behind the E1 test rows, as `<path under data/raw>\\t<source_file>` lines."""
    d = pd.read_parquet(Path(a.data_root) / "testbed" / "queries.parquet", columns=["source_file", "split"])
    raw = Path(a.raw)
    pcaps = sorted(p.relative_to(raw).as_posix() for p in raw.rglob("*.pcap*"))
    lines = []
    for src in sorted(d.loc[d["split"] == "test", "source_file"].unique()):
        hit = next((p for p in pcaps if p == src or p.endswith("/" + src)), None)
        if hit is None:
            raise SystemExit(f"no pcap under {raw} for {src}")
        lines.append(f"{hit}\t{src}")
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text("\n".join(lines) + "\n", newline="\n")
    print(f"{len(lines)} captures -> {a.out}")


def zeek_test_only(a):
    """Copy each capture's dns.log keeping the rows from its first test-split query on (the split is per capture)."""
    d = pd.read_parquet(Path(a.data_root) / "testbed" / "queries.parquet", columns=["source_file", "split", "ts"])
    start = d[d["split"] == "test"].groupby("source_file")["ts"].min()
    out = Path(a.out)
    kept = total = 0
    for sub in sorted(p for p in Path(a.zeek).iterdir() if (p / "dns.log").exists()):
        src = (sub / "source.txt").read_text().strip().split("\t")[1]
        rows = []
        for line in (sub / "dns.log").read_text().splitlines():
            if not line.startswith("#"):
                total += 1
                if float(line.split("\t", 1)[0]) < start[src] - 1e-6:
                    continue
                kept += 1
            rows.append(line)
        (out / sub.name).mkdir(parents=True, exist_ok=True)
        (out / sub.name / "dns.log").write_text("\n".join(rows) + "\n", newline="\n")
    print(f"kept {kept:,} of {total:,} dns.log rows -> {out}")


def rita(a):
    """Map RITA's findings (rita view --stdout) to the test rows: a query gets its domain's severity."""
    te = test_rows(Path(a.data_root))
    found = pd.read_csv(a.csv, skiprows=1)
    found = found[found["Subdomains"] > 0]
    q = te["qname"].astype(str).str.rstrip(".").str.lower()
    score = np.zeros(len(te))
    for _, row in found.iterrows():
        fqdn = str(row["FQDN"]).lower()
        hit = ((q == fqdn) | q.str.endswith("." + fqdn)).to_numpy()
        score[hit] = np.maximum(score[hit], RITA_SEVERITY.get(row["Severity"], 0.0))
    print(found[["Severity", "FQDN", "Subdomains", "C2 Over DNS Score"]].to_string(index=False))
    write(
        Path(a.out),
        "rita",
        te,
        score,
        threshold=RITA_SEVERITY["Medium"],
        meaning="RITA severity of the query's domain (DNS tunnelling by unique subdomains): 0 none, 0.25 Low, "
        "0.5 Medium, 0.75 High, 1 Critical",
        latency_ms=a.import_seconds * 1000 / len(te),
        config={
            "tool": "RITA v5.1.2 (default config), ClickHouse 24.1.6, Zeek 9.0.1 dns.log",
            "findings": found[["Severity", "FQDN", "Subdomains"]].to_dict("records"),
            "latency_note": "RITA import + analysis wall time per test row; RITA works on batches, not single queries",
        },
    )


# ---- Splunk pretrained model ------------------------------------------------------------------
# Follows Splunk's notebook detect_dns_data_exfiltration_using_pretrained_model_in_dsdl.ipynb
# (github.com/splunk/splunk-mltk-container-docker). Two changes so it runs as intended: bytes
# outside string.printable are escaped as \xNN (the notebook raises on them), and predictions keep
# row order (the notebook's DataLoader(shuffle=True) pairs them with the wrong rows).

KEYS = list(string.printable.strip())
KEY_INDEX = {c: i for i, c in enumerate(KEYS)}


def escape(q: str) -> str:
    return "".join(c if c in KEY_INDEX else "".join(f"{chr(92)}x{b:02x}" for b in c.encode()) for c in q)


def without_domain(q: str) -> str:
    return q.rsplit(".", 2)[0]


def domain(q: str) -> str:
    return q.replace(without_domain(q), "").lstrip(".")


def entropy(s: str) -> float:
    n = float(len(s))
    return -sum(c / n * math.log(c / n, 2) for c in Counter(s).values())


def splunk_features(te: pd.DataFrame, window: int = 10) -> np.ndarray:
    """94 printable-character counts, len and entropy of the name without its domain, and their means
    over the `window` latest queries from the same src and domain (current one included)."""
    names = te["qname"].astype(str).str.rstrip(".").map(escape)
    x = np.zeros((len(te), len(KEYS) + 4), dtype=np.float32)
    recent: dict = defaultdict(lambda: deque(maxlen=window))
    for i in np.lexsort((np.arange(len(te)), te["ts"].to_numpy())):
        name = names.iat[i]
        for c in name:
            x[i, KEY_INDEX[c]] += 1
        rest = without_domain(name)
        h = recent[(te["src_host"].iat[i], domain(name))]
        h.append((len(rest), entropy(rest)))
        x[i, len(KEYS) :] = [len(rest), entropy(rest), np.mean([v[0] for v in h]), np.mean([v[1] for v in h])]
    return x


def splunk(a):
    import torch
    from torch import nn

    net = nn.Sequential(
        nn.Linear(98, 128),
        nn.ReLU(),
        nn.Dropout(0.5),
        nn.Linear(128, 128),
        nn.ReLU(),
        nn.Dropout(0.5),
        nn.Linear(128, 1),
        nn.Sigmoid(),
    )
    state = torch.load(a.weights, map_location="cpu", weights_only=True)
    names = {"layer_1": "0", "layer_2": "3", "layer_out": "6"}  # the notebook's layer names -> Sequential indices
    net.load_state_dict({names[k.split(".")[0]] + "." + k.split(".")[1]: v for k, v in state.items()})
    net.eval()
    te = test_rows(Path(a.data_root))
    t0 = time.perf_counter()
    with torch.no_grad():
        p = net(torch.from_numpy(splunk_features(te))).squeeze(1).numpy()
    ms = (time.perf_counter() - t0) * 1000 / len(te)
    write(
        Path(a.out),
        "splunk_dsdl",
        te,
        p,
        threshold=0.5,
        meaning="Splunk pretrained MLP P(DNS exfiltration) (security_content, detection removed May 2026)",
        latency_ms=ms,
        config={
            "tool": "Splunk detect_dns_data_exfiltration_using_pretrained_model_in_dsdl",
            "weights": Path(a.weights).name,
            "window": 10,
            "changes": "non-printable bytes escaped as \\xNN; predictions kept in row order",
        },
    )


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--data-root", default=str(DATA_ROOT))
    ap.add_argument("--out", default="results_external")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("zeek-list")
    s.add_argument("--raw", default="data/raw")
    s.add_argument("--out", required=True)
    s = sub.add_parser("zeek-test-only")
    s.add_argument("--zeek", required=True)
    s.add_argument("--out", required=True)
    s = sub.add_parser("rita")
    s.add_argument("--csv", required=True, help="output of: rita view --stdout <database>")
    s.add_argument("--import-seconds", type=float, default=2.3, help="RITA import wall time, for the latency field")
    s = sub.add_parser("splunk")
    s.add_argument("--weights", required=True)
    a = ap.parse_args(argv)
    {"zeek-list": zeek_list, "zeek-test-only": zeek_test_only, "rita": rita, "splunk": splunk}[a.cmd](a)


if __name__ == "__main__":
    main()
