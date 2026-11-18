"""Ablation 2 (supervised fine-tune of DNS-BERT) CPU smoke tests: python -m pytest tests/test_m2_supervised.py -q"""

import json

import numpy as np
import pandas as pd

from models import m2_dnsbert, m2_supervised
from tests.test_m2 import BENIGN, TUNNEL, _df, _tiny

SUP_CFG = dict(max_steps=30, batch_size=32, device="cpu", lr=1e-3)


def _pretrained(tmp_path):
    path = tmp_path / "phase1"
    m2_dnsbert.save(_tiny("bpe"), path)
    return path


def _labelled():
    tun = [t.replace("evil", w) for t in TUNNEL for w in ["evil", "xx", "yy", "zz", "qq"]]
    return pd.concat([_df(BENIGN, 0), _df(tun * 4, 1)], ignore_index=True)


def test_sup_ranks_tunnels_higher(tmp_path):
    m = m2_supervised.train(_labelled(), {**SUP_CFG, "init_from": str(_pretrained(tmp_path))})
    s = m2_supervised.score(m, pd.concat([_df(BENIGN[:10], 0), _df(TUNNEL, 1)]))
    assert s.shape == (12,)
    assert s[10:].min() > np.median(s[:10])


def test_sup_scores_are_finite_and_unsaturated(tmp_path):
    m = m2_supervised.train(_labelled(), {**SUP_CFG, "init_from": str(_pretrained(tmp_path))})
    s = m2_supervised.score(m, pd.concat([_df(BENIGN[:10], 0), _df(TUNNEL, 1)]))
    assert np.isfinite(s).all()
    assert len(np.unique(s[10:])) == len(TUNNEL)  # logit margin: distinct tunnel names never tie at a cap


def test_sup_save_load_roundtrip(tmp_path):
    m = m2_supervised.train(_labelled(), {**SUP_CFG, "init_from": str(_pretrained(tmp_path))})
    test = pd.concat([_df(BENIGN[:10], 0), _df(TUNNEL, 1)])
    m2_supervised.save(m, tmp_path / "sup")
    again = m2_supervised.load(tmp_path / "sup", "cpu")
    np.testing.assert_allclose(m2_supervised.score(again, test), m2_supervised.score(m, test), rtol=1e-4)


def test_m2_run_sup_writes_folder_and_excludes_holdout(tmp_path, monkeypatch):
    from models import m2_run
    from scripts.make_synthetic_sample import make_sample

    (tmp_path / "testbed").mkdir()
    make_sample(600, seed=1).to_parquet(tmp_path / "testbed" / "queries.parquet")
    seen = {}
    real_train = m2_supervised.train

    def spy(train_df, cfg):
        seen["tools"] = set(train_df["tool"])
        seen["labels"] = set(train_df["label"])
        return real_train(train_df, cfg)

    monkeypatch.setattr(m2_supervised, "train", spy)
    m2_run.main(
        [
            "--model",
            "m2sup",
            "--exp",
            "E3",
            "--holdout",
            "iodine",
            "--root",
            str(tmp_path),
            "--init-from",
            str(_pretrained(tmp_path)),
            "--tag",
            "ablation2_sup",
            "--max-steps",
            "5",
            "--batch-size",
            "32",
            "--device",
            "cpu",
            "--latency-n",
            "2",
            "--out",
            str(tmp_path / "res"),
        ]
    )
    assert "iodine" not in seen["tools"] and seen["labels"] == {0, 1}
    for name in ["m2_ablation2_sup", "m2_ablation2_sup_hostavg"]:
        res = json.loads((tmp_path / f"res/{name}/E3_iodine.json").read_text())
        assert res["model"] == name and res["threshold"] is not None
        assert "info_bits" not in res and np.isfinite(res["scores"]).all()
