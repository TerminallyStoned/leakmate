"""Tests for scripts/build_queries_parquet.py: the bridge into eval/experiments.py.

Run from the repo root:  python3 -m pytest testbed/tools/tests -q
Needs pandas+pyarrow (the eval module needs them too); skipped if absent.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "build_queries_parquet.py"

pd = pytest.importorskip("pandas")


def row(ts: float, qname: str, host: str = "172.28.0.4", tool: str = "benign", label: int = 0) -> dict:
    return {
        "ts": ts,
        "src_host": host,
        "session_id": f"{host}-1",
        "qname": qname,
        "qtype": "A",
        "resp_size": 80,
        "rcode": "NOERROR",
        "label": label,
        "tool": tool,
        "dataset": "testbed",
        "throttle": "",
    }


def write_rows(path: Path, rows: list[dict]) -> Path:
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return path


def run(*argv: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(SCRIPT), *argv], capture_output=True, text=True)


def test_concatenates_sources_and_writes_the_contract_columns(tmp_path: Path) -> None:
    a = write_rows(tmp_path / "benign.ndjson", [row(100.0, "a.com"), row(102.0, "b.com")])
    b = write_rows(tmp_path / "tool.ndjson", [row(101.0, "x.tunnel.test", "172.28.0.44", "dns2tcp", 1)])
    out = tmp_path / "queries.parquet"
    res = run("--add", str(a), "--add", str(b), "--out", str(out))
    assert res.returncode == 0, res.stderr
    df = pd.read_parquet(out)
    assert list(df.columns) == [
        "ts", "src_host", "session_id", "qname", "qtype", "resp_size", "rcode",
        "label", "tool", "dataset", "throttle",
    ]
    assert df["qname"].tolist() == ["a.com", "x.tunnel.test", "b.com"], "must be time-ordered"
    assert sorted(df["tool"]) == ["benign", "dns2tcp", "benign"] or sorted(df["tool"].unique()) == ["benign", "dns2tcp"]


def test_identical_rows_from_the_same_file_are_dropped(tmp_path: Path) -> None:
    src = write_rows(tmp_path / "x.ndjson", [row(5.0, "dup.com")] * 3)
    out = tmp_path / "q.parquet"
    res = run("--add", str(src), "--out", str(out))
    assert res.returncode == 0, res.stderr
    assert len(pd.read_parquet(out)) == 1
    assert "duplicates dropped 2" in res.stdout


def test_two_views_of_one_capture_window_warn(tmp_path: Path) -> None:
    capture = write_rows(tmp_path / "pcap.ndjson", [row(10.0 + i, f"n{i}.com") for i in range(20)])
    sidecar = write_rows(
        tmp_path / "sidecar.ndjson",
        [row(10.04 + i, f"n{i}.com") for i in range(20)],  # same lookups, dig latency later
    )
    out = tmp_path / "q.parquet"
    res = run("--add", str(capture), "--add", str(sidecar), "--out", str(out))
    assert "two views of one capture window" in res.stderr, res.stderr


def test_rows_from_another_dataset_are_excluded(tmp_path: Path) -> None:
    mixed = write_rows(tmp_path / "m.ndjson", [row(1.0, "a.com"), row(2.0, "b.com")])
    out = tmp_path / "q.parquet"
    res = run("--add", str(mixed), "--out", str(out), "--dataset", "cic")
    assert res.returncode != 0
    assert "nothing to write" in res.stderr + res.stdout


def test_output_loads_through_the_eval_module(tmp_path: Path) -> None:
    """The point of the bridge: eval/experiments.py (Neo's card #10) reads it unchanged."""
    experiments = ROOT / "eval" / "experiments.py"
    if not experiments.exists():
        pytest.skip("eval/ is on the eval branch until card #10 merges")
    src = write_rows(
        tmp_path / "run.ndjson",
        [row(i * 1.0, f"host{i}.com") for i in range(30)]
        + [row(i * 1.0 + 0.5, f"t{i}.tunnel.test", "172.28.0.44", "dns2tcp", 1) for i in range(10)],
    )
    root = tmp_path / "processed"
    out = root / "testbed" / "queries.parquet"
    assert run("--add", str(src), "--out", str(out)).returncode == 0

    sys.path.insert(0, str(ROOT))
    try:
        from eval.experiments import get_split, load_queries, tools_in

        df = load_queries("testbed", root)
        assert len(df) == 40
        assert tools_in("testbed", root) == ["dns2tcp"]
        train, test, _ = get_split("E1", root)
        assert {"benign", "dns2tcp"} <= set(train["tool"]) | set(test["tool"])
        assert set(train["label"]) == {0, 1}, "every time window must hold both classes"
    finally:
        sys.path.remove(str(ROOT))
