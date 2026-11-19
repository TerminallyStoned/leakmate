"""Fast CPU smoke tests for M2 and the IF baseline: python -m pytest tests/test_m2.py -q"""
import math

import numpy as np
import pandas as pd

from models import iforest_baseline, m2_dnsbert

BENIGN = ["www.google.com", "api.github.com", "cdn.jsdelivr.net", "mail.yahoo.com", "static.xx.fbcdn.net",
          "login.microsoftonline.com", "img.youtube.com", "s3.amazonaws.com", "edge.apple.com", "app.slack.com"] * 20
TUNNEL = ["mzxw6ytboi2dsnrqgezdgnbvgy3tqojq.t.evil.net", "a1b2c3d4e5f60718293a4b5c6d7e8f90.c2.bad.org"]


def _df(names, label):
    return pd.DataFrame({"qname": names, "qtype": "A", "resp_size": 100, "label": label})


def _tiny(kind):
    cfg = dict(tokenizer=kind, vocab_size=300, num_layers=1, hidden=32, heads=2, intermediate=64,
               max_steps=60, batch_size=32, log_every=1000, device="cpu")
    return m2_dnsbert.train(_df(BENIGN, 0), cfg)


def test_m2_bpe_and_char_rank_tunnels_higher(tmp_path):
    for kind in ["bpe", "char"]:
        m = _tiny(kind)
        test = pd.concat([_df(BENIGN[:10], 0), _df(TUNNEL, 1)])
        s = m2_dnsbert.score(m, test)
        assert s.shape == (12,) and np.isfinite(s).all()
        assert s[10:].min() > np.median(s[:10])
        bits = m2_dnsbert._score_both(m, test, None)[1] / math.log(2)  # as models/m2_run.py writes info_bits
        assert (bits >= 0).all() and bits[10:].min() > bits[:10].max()
        m2_dnsbert.save(m, tmp_path / kind)
        np.testing.assert_allclose(m2_dnsbert.score(m2_dnsbert.load(tmp_path / kind, "cpu"), test), s, rtol=1e-4)


def test_batched_scoring_matches_unbatched():
    m = _tiny("bpe")
    test = pd.concat([_df(BENIGN[:10], 0), _df(TUNNEL, 1)])
    np.testing.assert_allclose(m2_dnsbert.score(m, test, batch_rows=4096),
                               m2_dnsbert.score(m, test, batch_rows=1), rtol=1e-4, atol=1e-5)


def test_iforest_trains_on_benign_only(tmp_path):
    train = pd.concat([_df(BENIGN, 0), _df(TUNNEL * 50, 1)])
    m = iforest_baseline.train(train, {"n_estimators": 50})
    s = iforest_baseline.score(m, pd.concat([_df(BENIGN[:10], 0), _df(TUNNEL, 1)]))
    assert s[10:].min() > s[:10].max()
    iforest_baseline.save(m, tmp_path / "if.joblib")
    assert iforest_baseline.load(tmp_path / "if.joblib")["cols"] == m["cols"]


def test_hold_out_benign_takes_latest_rows_of_every_capture():
    from models.m2_run import hold_out_benign
    df = pd.DataFrame({"ts": list(range(20)) * 2, "label": [0] * 40,
                       "source_file": ["a.pcap"] * 20 + ["b.pcap"] * 20})
    train, val = hold_out_benign(df, 0.1)
    assert sorted(val["source_file"].value_counts().to_dict().items()) == [("a.pcap", 2), ("b.pcap", 2)]
    assert set(val["ts"]) == {18, 19} and not set(val.index) & set(train.index)


def test_host_average_is_past_only_and_per_host():
    from models.m2_run import host_average
    df = pd.DataFrame({"ts": [0.0, 10.0, 20.0, 100.0, 5.0], "src_host": ["h1", "h1", "h1", "h1", "h2"]})
    avg = host_average(df, [1.0, 3.0, 5.0, 7.0, 100.0], window_s=15)
    np.testing.assert_allclose(avg, [1.0, 2.0, 4.0, 7.0, 100.0])  # h2 never mixes into h1


def test_continued_pretraining_keeps_tokenizer(tmp_path):
    base = _tiny("bpe")
    m2_dnsbert.save(base, tmp_path / "base")
    cont = m2_dnsbert.train(_df(BENIGN[:50], 0), dict(init_from=str(tmp_path / "base"), max_steps=5,
                                                      batch_size=16, log_every=1000, device="cpu"))
    assert cont.tokenizer.get_vocab() == base.tokenizer.get_vocab()
    assert cont.cfg["tokenizer"] == "bpe" and cont.cfg["hidden"] == base.cfg["hidden"]


def test_m2_run_main_writes_result_and_hostavg_per_model_folder(tmp_path):
    import json

    from models import m2_run
    from scripts.make_synthetic_sample import make_sample

    data = tmp_path / "q.parquet"
    make_sample(600, seed=1).to_parquet(data)
    m2_run.main(["--model", "iforest", "--exp", "E1", "--data", str(data), "--out", str(tmp_path / "res"),
                 "--latency-n", "2", "--save-model", str(tmp_path / "if.joblib")])
    base = json.loads((tmp_path / "res/iforest/E1.json").read_text())
    avg = json.loads((tmp_path / "res/iforest_hostavg/E1.json").read_text())
    assert base["model"] == "iforest" and avg["model"] == "iforest_hostavg"
    assert base["threshold"] is not None and avg["threshold"] is not None
    assert base["env"]["packages"]["scikit-learn"] and avg["env"] == base["env"]
    assert len(base["scores"]) == len(avg["scores"]) == base["n_test"] == len(base["session_ids"])
    # reuse the saved model: no training, same test rows
    m2_run.main(["--model", "iforest", "--exp", "E1", "--data", str(data), "--out", str(tmp_path / "res2"),
                 "--latency-n", "2", "--load-model", str(tmp_path / "if.joblib")])
    again = json.loads((tmp_path / "res2/iforest/E1.json").read_text())
    np.testing.assert_allclose(again["scores"], base["scores"], rtol=1e-6)
    assert again["train_time_s"] == 0.0


def test_migrate_layout_moves_variants_into_model_folders(tmp_path):
    import json

    from scripts.m2_phase2 import migrate_layout

    (tmp_path / "m2").mkdir()
    for stem, model in [("E1", "m2"), ("E3_iodine_hostavg", "m2_hostavg"),
                        ("E3_iodine_ablation1_char_hostavg", "m2_ablation1_char_hostavg")]:
        (tmp_path / "m2" / f"{stem}.json").write_text(json.dumps({"model": model}))
    migrate_layout(tmp_path)
    assert (tmp_path / "m2/E1.json").exists()
    assert (tmp_path / "m2_hostavg/E3_iodine.json").exists()
    assert (tmp_path / "m2_ablation1_char_hostavg/E3_iodine.json").exists()
    assert sorted(p.name for p in (tmp_path / "m2").iterdir()) == ["E1.json"]


def test_val_threshold_is_tie_aware():
    from models.m2_run import val_threshold

    # 2% of held-out benign share the 99th-percentile score (a repeated name)
    val = np.concatenate([np.linspace(0, 1, 980), np.full(20, 1.5)])
    t = val_threshold(val, 0.01)
    assert (val >= t).mean() <= 0.01  # a plain np.quantile(val, 0.99) would flag all 20 tied rows (2%)
    assert (np.quantile(val, 0.99) <= val).mean() > 0.01
