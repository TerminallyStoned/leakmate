"""Fake data so the eval module and M3 can be tested before real data exists.

    python scripts/make_fake_data.py results    # fake results JSONs  -> results/
    python scripts/make_fake_data.py queries    # fake query tables   -> data/processed/{cic,testbed}/

The fake query tables follow the CONTRACTS schema exactly. They are NOT realistic;
use them only to check that code runs end to end. Delete them once real data lands.
"""
from __future__ import annotations

import base64
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from eval.results_io import write_result  # noqa: E402

BENIGN = ["www.google.com", "api.github.com", "cdn.jsdelivr.net", "mail.yahoo.com",
          "updates.ubuntu.com", "d1x9a8f7.cloudfront.net", "static.xx.fbcdn.net",
          "ocsp.digicert.com", "fonts.gstatic.com", "login.microsoftonline.com"]
TOOLS = ["iodine", "dnscat2", "dns2tcp", "dnsexfiltrator"]


def fake_results(out_dir: Path, n: int = 4000, seed: int = 0) -> None:
    rng = np.random.default_rng(seed)
    models = {"m1_xgb": 2.5, "rf": 2.0, "m2_bert": 1.6, "m3_cnn": 2.2, "m3_bilstm": 2.1}
    latency = {"m1_xgb": 0.05, "rf": 0.2, "m2_bert": 14.0, "m3_cnn": 0.9, "m3_bilstm": 2.5}
    for exp in ["E1", "E2", "E3_iodine"]:
        labels = (rng.random(n) < 0.3).astype(int)
        tools = np.where(labels == 1, rng.choice(TOOLS, n), "benign")
        for model, sep in models.items():
            scores = 1 / (1 + np.exp(-(labels * sep * 2 - sep + rng.normal(0, 1, n))))
            write_result(out_dir / model / f"{exp}.json", scores, labels,
                         train_time_s=float(rng.uniform(5, 300)),
                         latency_ms=latency[model], config={"fake": True}, tools=tools)
    # Edge cases the module must survive.
    write_result(out_dir / "perfect" / "E1.json", [0.1, 0.2, 0.9, 0.8], [0, 0, 1, 1],
                 1.0, 0.1, {"fake": True})
    write_result(out_dir / "one_class" / "E1.json", [0.1, 0.2, 0.3], [0, 0, 0],
                 1.0, 0.1, {"fake": True})
    print(f"Fake results written under {out_dir}/")


def _tunnel_name(rng, tool: str) -> str:
    payload = base64.b32encode(rng.bytes(int(rng.integers(10, 40)))).decode().rstrip("=")
    labels = [payload[i:i + 50] for i in range(0, len(payload), 50)]
    if tool == "dnscat2":
        labels = [payload.lower().encode().hex()[:60]]
    return ".".join(labels + [f"t{TOOLS.index(tool)}", "tunnel.test"])


def fake_queries(root: Path, n: int = 6000, seed: int = 0) -> None:
    rng = np.random.default_rng(seed)
    for dataset in ["cic", "testbed"]:
        rows = []
        for i in range(n):
            tunnel = rng.random() < 0.3
            tool = rng.choice(TOOLS) if tunnel else "benign"
            host = f"10.0.0.{rng.integers(2, 12)}"
            rows.append({
                "ts": 1_700_000_000 + i * float(rng.uniform(0.05, 2)),
                "src_host": host,
                "session_id": f"{dataset}-{host}-{tool}-{i // 200}",
                "qname": _tunnel_name(rng, tool) if tunnel else str(rng.choice(BENIGN)),
                "qtype": "TXT" if tunnel else "A",
                "resp_size": int(rng.integers(60, 400)),
                "rcode": 0,
                "label": int(tunnel),
                "tool": tool,
                "dataset": dataset,
                "throttle": float(rng.choice([0, 0, 0, 0.5])) if tunnel else 0.0,
            })
        out = root / dataset
        out.mkdir(parents=True, exist_ok=True)
        pd.DataFrame(rows).to_parquet(out / "queries.parquet", index=False)
    print(f"Fake query tables written under {root}/{{cic,testbed}}/queries.parquet")


if __name__ == "__main__":
    what = sys.argv[1] if len(sys.argv) > 1 else "results"
    if what == "results":
        fake_results(ROOT / "results")
    elif what == "queries":
        fake_queries(ROOT / "data" / "processed")
    else:
        raise SystemExit("usage: make_fake_data.py [results|queries]")
