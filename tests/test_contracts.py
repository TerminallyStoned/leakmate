from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from make_synthetic_sample import make_sample  # noqa: E402

from contracts import ContractError, validate  # noqa: E402


def test_valid_sample_and_committed_results_pass() -> None:
    """The 1,000-row synthetic sample and every committed results file follow the contract."""
    df = make_sample()
    assert len(df) == 1000 and set(df["tool"]) > {"benign"}
    validate(df)
    files = sorted(p for p in (ROOT / "results").glob("*/*.json"))
    assert files
    for p in files:
        validate(json.loads(p.read_text()))


def test_invalid_inputs_name_the_bad_column_and_key() -> None:
    """Broken tables and results raise ContractError naming each problem and its fix."""
    df = make_sample(n=200).drop(columns=["throttle"])
    df["ts"] = df["ts"] * 1000
    df.loc[df.index[0], "qtype"] = "None"
    df.loc[df.index[1], "tool"] = "iodine2"
    with pytest.raises(ContractError) as e:
        validate(df)
    msg = str(e.value)
    for needle in [
        "missing required column 'throttle'",
        "not epoch seconds",
        "column 'qtype'",
        "qtype_name",
        "column 'tool'",
    ]:
        assert needle in msg, needle

    res = {
        "model": "m1",
        "experiment": "E9",
        "dataset": ["cic"],
        "split": "split_column",
        "n_train": 10,
        "n_test": 3,
        "scores": [0.1, float("nan"), 0.9],
        "labels": [0, 1],
        "tools": ["benign", "iodine", "x"],
        "src_hosts": ["10.0.0.1"] * 3,
        "train_time_s": 1.0,
        "latency_ms_per_query": 2.0,
        "score_meaning": "P(tunnel)",
        "config": {},
    }
    with pytest.raises(ContractError) as e:
        validate(res)
    msg = str(e.value)
    for needle in [
        "missing required key 'created_utc'",
        "key 'experiment'",
        "key 'labels' has 2 entries",
        "key 'scores': 1 entries are not finite",
        "key 'tools'",
    ]:
        assert needle in msg, needle
