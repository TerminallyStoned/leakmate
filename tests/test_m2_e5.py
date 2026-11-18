"""Experiment 5 derived from Experiment 1 must equal a direct E5 run: python -m pytest tests/test_m2_e5.py -q"""

import json

import numpy as np
import pandas as pd

from eval.experiments import LOW_AND_SLOW_MS


def _table(tmp_path):
    from scripts.make_synthetic_sample import make_sample

    df = make_sample(600, seed=1)
    tun_test = df[(df["label"] == 1) & (df["split"] == "test")]
    slow = tun_test["session_id"].drop_duplicates().iloc[:2].tolist()  # two tunnel sessions become low-and-slow
    df.loc[df["session_id"].isin(slow) & (df["label"] == 1), "throttle"] = 2 * LOW_AND_SLOW_MS
    (tmp_path / "testbed").mkdir()
    df.to_parquet(tmp_path / "testbed" / "queries.parquet")
    return df


def test_derive_e5_matches_direct_run(tmp_path):
    from models import m2_run
    from scripts.m2_e5 import derive_e5

    df = _table(tmp_path)
    common = [
        "--model",
        "m2",
        "--root",
        str(tmp_path),
        "--latency-n",
        "2",
        "--device",
        "cpu",
        "--vocab-size",
        "200",
        "--max-steps",
        "5",
        "--batch-size",
        "32",
    ]
    m2_run.main([*common, "--exp", "E1", "--out", str(tmp_path / "e1"), "--save-model", str(tmp_path / "mdl")])
    m2_run.main([*common, "--exp", "E5", "--out", str(tmp_path / "e5"), "--load-model", str(tmp_path / "mdl")])

    e1 = json.loads((tmp_path / "e1/m2/E1.json").read_text())
    e1h = json.loads((tmp_path / "e1/m2_hostavg/E1.json").read_text())
    thr = df.set_index("session_id")["throttle"]
    throttle = [int(thr[s].max()) if lab else 0 for s, lab in zip(e1["session_ids"], e1["labels"])]
    got, got_h = derive_e5(e1, throttle, e1h)

    for derived, name in [(got, "m2"), (got_h, "m2_hostavg")]:
        direct = json.loads((tmp_path / f"e5/{name}/E5.json").read_text())
        assert derived["experiment"] == "E5" and derived["n_test"] == direct["n_test"]
        assert derived["labels"] == direct["labels"] and derived["session_ids"] == direct["session_ids"]
        np.testing.assert_allclose(derived["scores"], direct["scores"], rtol=1e-5)
        assert derived["threshold"] == direct["threshold"]
    assert sum(got["labels"]) > 0 and len(got["info_bits"]) == got["n_test"]


def test_row_throttle_defaults_to_zero(tmp_path):
    from scripts.m2_e5 import row_throttle

    man = tmp_path / "manifest.csv"
    pd.DataFrame({"file": ["tools/a.pcap", "tools/b.pcap"], "throttle_ms": [10000, 0]}).to_csv(man, index=False)
    sids = ["tools/a.pcap|1.2.3.4|0", "tools/b.pcap|1.2.3.4|0", "benign/x.pcap|5.6.7.8|0", "tools/a.pcap|1.2.3.4|1"]
    assert row_throttle(sids, [1, 1, 1, 0], man) == [10000, 0, 0, 0]
