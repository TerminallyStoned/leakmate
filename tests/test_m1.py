"""Fast CPU smoke tests for M1 (XGBoost + SHAP) and its RF baseline:
python -m pytest tests/test_m1.py -q
"""
import base64
import json
import random

import numpy as np
import pandas as pd

from contracts import assign_sessions, validate
from models import host_features, m1_features, m1_run, m1_xgb, rf_baseline

BENIGN = ["www.google.com", "api.github.com", "cdn.jsdelivr.net", "mail.yahoo.com", "static.xx.fbcdn.net",
          "login.microsoftonline.com", "img.youtube.com", "s3.amazonaws.com", "edge.apple.com", "app.slack.com"]


def _tunnel(rnd):
    payload = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(20, 40)))
    return base64.b32encode(payload).decode().rstrip("=").lower()[:60] + ".t.evil-tun.net"


def _table(n=600, seed=0, cic=False):
    """Contract-valid query table (docs/contracts.md, section 1).

    Benign hosts browse slowly; one tunnel host sends many unique names fast."""
    rnd, rows, t = random.Random(seed), [], 1_700_000_000.0
    for _ in range(n):
        t += rnd.expovariate(4)
        if rnd.random() < 0.3:
            q, lab, tool, host, qt = _tunnel(rnd), 1, "iodine", "10.0.0.66", "TXT"
        else:
            q, lab, tool, host, qt = rnd.choice(BENIGN), 0, "benign", f"10.0.0.{rnd.randint(2, 9)}", "A"
        row = dict(ts=t, src_host=host, qname=q, qtype=qt,
                   resp_size=rnd.randint(40, 300), rcode=0, label=lab, tool=tool, dataset="synthetic", throttle=0)
        if cic:
            row.update(qname_truncated=lab == 1, qlen_wire=len(q) + 18, source_file="f.pcap")
        rows.append(row)
    df = pd.DataFrame(rows)
    df["session_id"] = assign_sessions(df)
    df["split"] = ["train" if i < int(n * 0.7) else "test" for i in range(n)]
    return df


def test_fixture_tables_follow_the_contract():
    validate(_table())
    validate(_table(cic=True))


def test_host_features_are_past_only_and_count_window():
    df = pd.DataFrame({"ts": [0.0, 10.0, 20.0, 100.0], "src_host": ["h"] * 4,
                       "qname": ["a.x.com", "b.x.com", "a.x.com", "c.x.com"], "qtype": ["A", "TXT", "A", "A"]})
    h = host_features.compute(df, window_s=60)
    assert list(h["h_qpm"]) == [1.0, 2.0, 3.0, 1.0]           # 100 s is outside (40, 100]
    assert h["h_uniq_ratio"].iloc[2] == 2 / 3 and h["h_parent_uniq"].iloc[2] == 2
    assert np.isclose(h["h_txt_null_ratio"].iloc[2], 1 / 3)
    # adding later rows must not change earlier rows (no look-ahead)
    more = pd.concat([df, pd.DataFrame({"ts": [101.0], "src_host": ["h"], "qname": ["z.y.org"], "qtype": ["A"]})],
                     ignore_index=True)
    pd.testing.assert_frame_equal(host_features.compute(more, 60).iloc[:4], h)


def test_m1_and_rf_rank_tunnels_higher(tmp_path):
    df = m1_features.attach(_table())
    train, test = df[df.split == "train"], df[df.split == "test"]
    for mod in [m1_xgb, rf_baseline]:
        m = mod.train(train, {"n_estimators": 60, "n_jobs": 1})
        s = mod.score(m, test)
        y = test["label"].to_numpy()
        assert s.shape == (len(test),) and np.isfinite(s).all()
        assert s[y == 1].min() > np.median(s[y == 0])
        mod.save(m, tmp_path / f"{mod.__name__}.joblib")
        np.testing.assert_allclose(mod.score(mod.load(tmp_path / f"{mod.__name__}.joblib"), test), s, rtol=1e-6)
        # raw rows (no precomputed f_ columns) score too, as the live detector would
        raw = test[[c for c in test.columns if not c.startswith(m1_features.PREFIX)]]
        assert np.isfinite(mod.score(m, raw.iloc[:1])).all()


def test_m1_early_stopping_keeps_probabilities_confident():
    # On separable data AUC-PR saturates after a tree or two; stopping on it would leave
    # scores stuck near 0.4/0.6. Early stopping must be driven by logloss instead.
    df = m1_features.attach(_table(n=1500))
    train, test = df[df.split == "train"], df[df.split == "test"]
    m = m1_xgb.train(train, {"n_jobs": 1})
    s, y = m1_xgb.score(m, test), test["label"].to_numpy()
    assert m["best_iteration"] is None or m["best_iteration"] > 10
    assert np.median(s[y == 1]) > 0.9 and np.median(s[y == 0]) < 0.1


def test_host_windows_never_mix_capture_files():
    # same IP in two different pcaps (CIC reuses addresses across captures)
    df = pd.DataFrame({"ts": [0.0, 1.0, 2.0], "src_host": ["10.0.0.5"] * 3,
                       "qname": ["a.x.com", "b.x.com", "c.x.com"], "qtype": "A",
                       "source_file": ["benign/a.pcap", "attack/b.pcap", "attack/b.pcap"]})
    h = host_features.compute(df, 60, key=m1_features.host_key(df))
    assert list(h["h_qpm"]) == [1.0, 1.0, 2.0]                 # row 1 starts a fresh window


def test_qlen_wire_kept_from_table_else_estimated():
    with_wire = pd.DataFrame({"qname": ["abc.example.com"], "qlen_wire": [250]})
    no_wire = pd.DataFrame({"qname": ["abc.example.com."]})
    assert m1_features.qlen_wire(with_wire).iloc[0] == 250       # CIC: true size from the extractor
    assert m1_features.qlen_wire(no_wire).iloc[0] == len("abc.example.com") + 18


def test_cic_leaky_features_dropped_unless_asked():
    df = m1_features.attach(_table(cic=True))
    train = df[df.split == "train"]
    m = m1_xgb.train(train, {"n_estimators": 20, "n_jobs": 1})
    assert not set(m1_features.CIC_LEAKY) & set(m["cols"])
    assert {"n_labels", "sub_entropy", "h_parent_uniq"}.isdisjoint(m["cols"])   # lost-domain group
    assert {"qlen_wire", "entropy", "h_uniq_ratio"} <= set(m["cols"])
    m_leaky = m1_xgb.train(train, {"n_estimators": 20, "n_jobs": 1, "keep_cic_leaky": True})
    assert set(m1_features.CIC_LEAKY) <= set(m_leaky["cols"])
    m_qt = m1_xgb.train(train, {"n_estimators": 20, "n_jobs": 1, "keep_cic_leaky": ["qtype"]})
    assert "qtype_code" in m_qt["cols"] and "q_len" not in m_qt["cols"]        # per-group ablation
    r = rf_baseline.train(train, {"n_estimators": 20, "n_jobs": 1})
    assert r["cols"] == m["cols"]                              # M1 and RF see identical inputs
    # non-CIC tables keep everything, including ones that carry qname_truncated but never truncate
    clean = m1_features.attach(_table())
    assert set(m1_features.CIC_LEAKY) <= set(m1_xgb.train(clean[clean.split == "train"],
                                                          {"n_estimators": 20, "n_jobs": 1})["cols"])
    untruncated = _table(cic=True).assign(qname_truncated=False)
    assert not m1_features.is_cic_table(untruncated)
    assert m1_features.drop_list(untruncated) == []


def test_shap_values_add_up_and_explain():
    df = m1_features.attach(_table())
    train, test = df[df.split == "train"], df[df.split == "test"].iloc[:50]
    m = m1_xgb.train(train, {"n_estimators": 60, "n_jobs": 1})
    vals, base, X = m1_xgb.shap_values(m, test)
    assert vals.shape == (len(test), len(m["cols"]))
    p = m1_xgb.score(m, test).astype(np.float64)
    logit = np.log(np.clip(p, 1e-7, 1 - 1e-7) / np.clip(1 - p, 1e-7, 1))
    np.testing.assert_allclose(vals.sum(axis=1) + base, logit, atol=1e-3)   # SHAP efficiency property
    ex = m1_xgb.explain(m, test.iloc[:3], top_k=2)
    assert len(ex) == 3 and all(len(e["top"]) == 2 for e in ex)
    assert all(t["feature"] in m["cols"] for e in ex for t in e["top"])


def test_runner_writes_contract_json(tmp_path):
    data = tmp_path / "q.parquet"
    _table(cic=True).to_parquet(data, index=False)
    for model in ["m1", "rf"]:
        out = m1_run.main(["--model", model, "--exp", "E2", "--data", str(data), "--out", str(tmp_path / "res"),
                           "--n-estimators", "40", "--latency-n", "5", "--shap-n", "100"])
        res = json.loads(out.read_text())
        validate(res)                                          # shared results contract
        for k in ["feature_cols", "session_ids", "ts"]:
            assert k in res, k
        assert len(res["scores"]) == len(res["session_ids"]) == len(res["ts"]) == res["n_test"]
        assert res["split"] == "split_column" and "qtype_code" in res["dropped_cols"]
    shap_json = json.loads((tmp_path / "res" / "m1" / "shap" / "E2_shap.json").read_text())
    assert shap_json["mean_abs_shap"] and shap_json["examples"]["top_scored_tunnels"]
    # per-group ablation flag and E4-style separate test table
    out = m1_run.main(["--model", "m1", "--exp", "E2", "--data", str(data), "--out", str(tmp_path / "res"),
                       "--n-estimators", "20", "--latency-n", "3", "--no-shap",
                       "--keep-cic-leaky", "qtype", "--tag", "ablation_cic_qtype"])
    res = json.loads(out.read_text())
    assert "qtype_code" in res["feature_cols"] and "q_len" in res["dropped_cols"]
    test = tmp_path / "t.parquet"
    _table(n=200, seed=1).to_parquet(test, index=False)
    out = m1_run.main(["--model", "rf", "--exp", "E4", "--data", str(data), "--test-data", str(test),
                       "--out", str(tmp_path / "res"), "--n-estimators", "20", "--latency-n", "3"])
    res = json.loads(out.read_text())
    assert res["n_test"] == 200 and res["split"].startswith("train=")


def test_cic_truncated_qname_has_no_trailing_dot():
    # snaplen can cut a packet right after a label's length byte; the name must not end with "."
    import cic_to_queries  # scripts/ is on the pytest path

    hdr = bytes(12)
    assert cic_to_queries._qname(hdr + b"\x03abc\x09wordpress\x03") == ("abc.wordpress", True, None)
    assert cic_to_queries._qname(hdr + b"\x03abc\x09wordpress\x03co") == ("abc.wordpress.co", True, None)
    assert cic_to_queries._qname(hdr + b"\x03abc\x03com\x00\x00\x01") == ("abc.com", False, 21)
