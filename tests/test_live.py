"""live/: replay hand-built captures through the sniffer pipeline and check what lands in alerts.db."""

import json
import sqlite3

import numpy as np
import pandas as pd
import pytest
from test_parser import _dns, _pcap, _query, _reply

from live.__main__ import main
from live.capture import pcap_frames
from live.pipeline import QUERY_COLS, HostWindows, QueryAssembler
from live.scorers import M1_WEIGHTS, load_scorer
from live.store import ALERT_COLS
from models import m1_features, m1_xgb
from parser.pcap import parse_pcap

RESOLVER, UPSTREAM, VICTIM, BENIGN = "172.28.0.2", "1.1.1.1", "172.28.0.31", "172.28.0.4"
LONG = "a1b2c3d4e5f6" * 9  # one 108-character label, far longer than any name the benign host sends


def _capture(path, n=30):
    """A tunnel client and a benign host, both through the resolver, which forwards every lookup."""
    frames = []
    for i in range(n):
        t = 1000.0 + i * 0.5
        for host, name, qtype in ((VICTIM, f"{i:02d}{LONG[: 60 - (i % 4)]}.{LONG[:40]}.d.tunnel.test", 16),
                                  (BENIGN, f"www{i % 7}.example.com", 1)):  # fmt: skip
            q, port = _query(i, name, qtype), 40000 + i
            frames += [
                (t, _dns(host, RESOLVER, port, 53, q)),
                (t + 0.01, _dns(RESOLVER, UPSTREAM, port + 1000, 53, q)),  # the resolver's own copy: ignored
                (t + 0.02, _dns(UPSTREAM, RESOLVER, 53, port + 1000, _reply(q))),
                (t + 0.03, _dns(RESOLVER, host, 53, port, _reply(q))),
            ]
            t += 0.1
    frames.sort(key=lambda f: f[0])
    _pcap(path, frames)
    return path


def _alerts(db):
    with sqlite3.connect(db) as con:
        return pd.read_sql("SELECT * FROM alerts ORDER BY id", con), pd.read_sql("SELECT * FROM host_stats", con)


def test_replay_writes_alerts_for_the_tunnel_only(tmp_path):
    db = tmp_path / "alerts.db"
    main(["--pcap", str(_capture(tmp_path / "cap.pcap")), "--db", str(db), "--model", "dummy"])
    alerts, stats = _alerts(db)
    assert list(alerts.columns) == ["id", *ALERT_COLS]
    assert len(alerts) == 30 and set(alerts.src_host) == {VICTIM}  # every tunnel query, no benign one
    assert alerts.qname.str.endswith(".d.tunnel.test").all() and (alerts.qtype == "TXT").all()
    assert (alerts.score >= alerts.threshold).all() and set(alerts.model) == {"dummy"}
    assert alerts.ts.is_monotonic_increasing and (alerts.detected_ts > 0).all()
    top = json.loads(alerts.top_features[0])
    assert [t["feature"] for t in top] == ["q_len", "entropy", "h_qpm"] and top[0]["value"] > 100
    assert stats.groupby("src_host").queries.sum().to_dict() == {VICTIM: 30, BENIGN: 30}  # resolver copies not counted
    assert stats.groupby("src_host").alerts.sum().to_dict() == {VICTIM: 30, BENIGN: 0}


def test_live_features_equal_the_offline_ones(tmp_path):
    """Released in small batches, every query gets exactly the features the file parser would give it."""
    cap = _capture(tmp_path / "cap.pcap")
    offline = parse_pcap(cap, lambda src, _q: None if src == RESOLVER else "benign")
    want = m1_features.build(offline[QUERY_COLS])

    asm, windows, rows, feats = QueryAssembler([RESOLVER]), HostWindows(), [], []
    for k, (ts, buf) in enumerate(pcap_frames(cap)):
        asm.feed(ts, buf)
        if k % 7 == 0:  # uneven batches, some empty
            batch = asm.release(ts)
            if batch:
                rows += batch
                feats.append(windows.features(batch))
    last = asm.release()
    rows += last
    feats.append(windows.features(last))

    assert pd.DataFrame(rows)[QUERY_COLS].to_dict("list") == offline[QUERY_COLS].to_dict("list")
    got = pd.concat(feats, ignore_index=True)
    assert list(got.columns) == list(want.columns)
    np.testing.assert_allclose(got.to_numpy(), want.to_numpy(), rtol=0, atol=1e-9)
    assert got.h_qpm.max() > 10  # the windows really do span earlier batches


def test_unanswered_query_is_released_after_the_wait_in_order():
    asm = QueryAssembler(reply_wait=1.0)
    asm.feed(10.0, _dns(VICTIM, RESOLVER, 5000, 53, _query(1, "no.reply.example.com")))
    asm.feed(10.1, _dns(VICTIM, RESOLVER, 5000, 53, _query(1, "no.reply.example.com")))  # retransmission: dropped
    q2 = _query(2, "answered.example.com")
    asm.feed(10.2, _dns(VICTIM, RESOLVER, 5001, 53, q2))
    asm.feed(10.3, _dns(RESOLVER, VICTIM, 53, 5001, _reply(q2, 3)))
    assert asm.release(10.9) == []  # the answered query waits behind the unanswered one
    first, second = asm.release(11.0)
    assert (first["qname"], first["resp_size"], first["rcode"]) == ("no.reply.example.com", 0, -1)
    assert (second["qname"], second["rcode"]) == ("answered.example.com", 3) and second["resp_size"] > 0
    asm.feed(11.5, _dns(RESOLVER, VICTIM, 53, 5000, _reply(_query(1, "no.reply.example.com"))))  # too late: ignored
    asm.feed(12.0, b"\x00" * 20)  # malformed frame: skipped
    assert asm.release() == []


def test_a_contract_model_plugs_in_with_its_explanations(tmp_path):
    """M1 through load/score/explain: alerts carry its top SHAP features."""
    cap = _capture(tmp_path / "cap.pcap")
    table = parse_pcap(cap, lambda src, _q: None if src == RESOLVER else ("dnscat2" if src == VICTIM else "benign"))
    weights = tmp_path / "m1.joblib"
    m1_xgb.save(m1_xgb.train(table, {"n_estimators": 20, "early_stopping_rounds": 0}), weights)  # no threshold

    db = tmp_path / "alerts.db"
    args = ["--pcap", str(cap), "--db", str(db), "--model", "m1", "--weights", str(weights), "--batch", "0.2"]
    with pytest.raises(SystemExit, match="no threshold of its own"):  # never a silent 0.5
        main(args)
    main([*args, "--threshold", "0.5"])
    alerts, _ = _alerts(db)
    assert set(alerts.src_host) == {VICTIM} and len(alerts) == 30 and set(alerts.model) == {"m1_xgb"}
    top = json.loads(alerts.top_features.iloc[-1])
    assert len(top) == 3 and all(isinstance(t["shap"], float) and t["feature"] for t in top)
    with sqlite3.connect(db) as con:
        meta = dict(con.execute("SELECT key, value FROM meta"))
    assert meta["model"] == "m1_xgb" and meta["schema_version"] == "1" and meta["source"] == str(cap)


def test_every_batch_is_timed_and_the_report_reads_it_back(tmp_path):
    from live import report

    db = tmp_path / "alerts.db"
    main(["--pcap", str(_capture(tmp_path / "cap.pcap")), "--db", str(db), "--batch", "0.2", "--model", "dummy"])
    data = report.load(db)
    b = data["batches"]
    assert len(b) > 5 and b.queries.sum() == 60 and b.alerts.sum() == 30  # every query is in exactly one batch
    assert (b.process_ms > 0).all() and (b.first_ts <= b.last_ts).all() and b.first_ts.is_monotonic_increasing

    hosts = report.per_host(data["hosts"], report.LAB_TOOLS).set_index("src_host")
    assert hosts.loc[VICTIM, ["traffic", "queries", "alerts", "flagged"]].tolist() == ["dnscat2", 30, 30, 1.0]
    assert hosts.loc[BENIGN, ["traffic", "queries", "alerts", "flagged"]].tolist() == ["benign", 30, 0, 0.0]
    tot = report.totals(report.per_host(data["hosts"], report.LAB_TOOLS)).set_index("kind")
    assert tot.loc["tunnel", "flagged"] == 1.0 and tot.loc["benign", "flagged"] == 0.0

    lat = report.latency(data["alerts"], b)
    assert lat["queries"] == 60 and lat["ms_per_query"] > 0 and lat["batch_queries_max"] <= 60
    text = report.render(data, report.LAB_TOOLS)
    assert "| 172.28.0.31 | dnscat2 | 30 | 30 | 100.00% |" in text
    assert "Time to alert: not measured" in text  # a replayed packet's timestamp is not on the wall clock
    report.main(["--db", str(db), "--out", str(tmp_path / "run.md")])
    assert (tmp_path / "run.md").read_text(encoding="utf-8") == text

    # the same rows as a sniffer would have written them: alerts 0.3 s after their packets
    data["meta"].loc[data["meta"]["key"] == "mode", "value"] = "sniff"
    data["alerts"]["detected_ts"] = data["alerts"]["ts"] + 0.3
    assert "30 alerts: median 0.30 s, 95th percentile 0.30 s, max 0.30 s" in report.render(data, report.LAB_TOOLS)


def test_no_model_flag_runs_m1_from_its_default_file(tmp_path, monkeypatch):
    """`python -m live` with no --model is M1 from artifacts/m1_xgb/E1.pt, and never the placeholder."""
    cap = _capture(tmp_path / "cap.pcap")
    monkeypatch.chdir(tmp_path)  # the default file is looked up from the working directory (the repo root)
    args = ["--pcap", str(cap), "--db", str(tmp_path / "alerts.db")]
    with pytest.raises(SystemExit, match="not found: the live detector runs M1 by default") as err:
        main(args)
    assert M1_WEIGHTS in str(err.value) and "--model dummy" in str(err.value)
    assert not (tmp_path / "alerts.db").exists()  # nothing was scored by a fallback

    table = parse_pcap(cap, lambda src, _q: None if src == RESOLVER else ("dnscat2" if src == VICTIM else "benign"))
    model = m1_xgb.train(table, {"n_estimators": 20})
    assert model["threshold"] is not None  # trained the normal way, M1 carries its own threshold
    m1_xgb.save(model, tmp_path / M1_WEIGHTS)
    main(args)
    alerts, stats = _alerts(tmp_path / "alerts.db")
    assert set(alerts.model) == {"m1_xgb"} and set(alerts.src_host) == {VICTIM} and len(alerts) == 30
    assert (alerts.threshold == model["threshold"]).all()
    assert stats.groupby("src_host").alerts.sum().to_dict() == {VICTIM: 30, BENIGN: 0}

    with pytest.raises(SystemExit, match="--model rf needs --weights"):  # the default file is M1's alone
        main([*args, "--model", "rf"])


def test_an_alias_for_several_models_asks_to_pick_one():
    with pytest.raises(SystemExit, match="m3_cnn, m3_bilstm"):
        load_scorer("m3", "unused.joblib")
