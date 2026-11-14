"""parser/testbed.py on hand-built lab captures: four tools, a slow run, and benign at the resolver."""

import pytest
from test_parser import _dns, _pcap, _query, _reply

from eval.experiments import get_split
from parser import testbed

SERVER, RESOLVER, UPSTREAM = "172.28.0.3", "172.28.0.2", "1.1.1.1"
TOOLS = {"172.28.0.44": "dns2tcp", "172.28.0.43": "dnsexfiltrator", "172.28.0.45": "iodine", "172.28.0.46": "dnscat2"}


def _tool_capture(path, client, n=10, t0=0.0, torn=False):
    frames = []
    for i in range(n):
        q = _query(100 + i, f"{i}.aGVsbG8gd29ybGQgdHVubmVs.tunnel.test")
        frames += [
            (t0 + i, _dns(client, SERVER, 40000 + i, 53, q)),
            (t0 + i + 0.1, _dns(SERVER, client, 53, 40000 + i, _reply(q))),
        ]
    frames.insert(1, frames[0])  # retransmission before the reply: kept once
    _pcap(path, frames)
    if torn:
        with open(path, "ab") as f:  # what a SIGTERM'd tcpdump leaves behind
            f.write(b"\x00" * 12)


def _resolver_capture(path, n=10):
    frames = []
    for i in range(n):
        host = f"172.28.0.{50 + i % 2}"
        q = _query(200 + i, f"www{i}.example.com", 1)
        fwd = _query(300 + i, f"www{i}.example.com", 1)  # the resolver asking upstream: same lookup again
        frames += [
            (1000.0 + i, _dns(host, RESOLVER, 50000 + i, 53, q)),
            (1000.01 + i, _dns(RESOLVER, UPSTREAM, 33000 + i, 53, fwd)),
            (1000.05 + i, _dns(UPSTREAM, RESOLVER, 53, 33000 + i, _reply(fwd))),
            (1000.06 + i, _dns(RESOLVER, host, 53, 50000 + i, _reply(q))),
        ]
    _pcap(path, frames)


def _captures(tmp_path):
    caps = []
    for k, (ip, tool) in enumerate(TOOLS.items()):
        p = tmp_path / "tools" / f"{tool}.pcap"
        p.parent.mkdir(exist_ok=True)
        _tool_capture(p, ip, t0=k * 100.0, torn=tool == "dns2tcp")
        caps.append((p, 0))
    slow = tmp_path / "tools" / "dnsexfiltrator_slow.pcap"
    _tool_capture(slow, "172.28.0.43", t0=500.0)
    res = tmp_path / "benign" / "resolver.pcap"
    res.parent.mkdir()
    _resolver_capture(res)
    return [*caps, (slow, 200), (res, 0)]


def test_testbed_table(tmp_path):
    df = testbed.build(_captures(tmp_path), TOOLS)  # validates against the contract
    assert df.groupby("tool").size().to_dict() == {
        "benign": 10,  # resolver's forwarded copies dropped
        "dns2tcp": 10,  # retransmission dropped, torn last record ignored
        "dnscat2": 10,
        "dnsexfiltrator": 20,
        "iodine": 10,
    }
    assert df[df.throttle > 0].source_file.str.endswith("/dnsexfiltrator_slow.pcap").all()
    assert (df[df.source_file.str.endswith("_slow.pcap") & (df.label == 1)].throttle == 200).all()
    assert (df[df.tool == "benign"].throttle == 0).all() and (df.resp_size > 0).all() and (df.rcode == 0).all()


def test_experiment_splits(tmp_path):
    out = tmp_path / "processed" / "testbed" / "queries.parquet"
    testbed.main([*(f"--capture={p}@{ms}" for p, ms in _captures(tmp_path)),
                  "--tools-map", "172.28.0.45=iodine,172.28.0.46=dnscat2", "--out", str(out)])  # fmt: skip
    root = out.parent.parent
    tr, te, *_ = get_split("E1", root)
    for side in (tr, te):
        assert set(side.tool) == {"benign", *TOOLS.values()}  # every tool in train and test
    for tool in TOOLS.values():
        tr, te, *_ = get_split("E3", root, holdout_tool=tool)
        assert tool not in set(tr.tool) and tool in set(te.tool)
    tr, te, *_ = get_split("E5", root)
    assert (tr.throttle == 0).all() and (te.throttle > 0).any()


def test_capture_behind_resolver_fails_loudly(tmp_path):
    p = tmp_path / "tools" / "iodine.pcap"
    p.parent.mkdir()
    _tool_capture(p, RESOLVER)  # captured at attacker-ns: every query arrives from the resolver
    with pytest.raises(SystemExit, match="no client DNS queries"):
        testbed.build([(p, 0)], TOOLS)


def test_runs_keep_their_own_source_file(tmp_path):
    caps = []
    for run in ("run_a", "run_b"):
        p = tmp_path / "benign" / run / "resolver.pcap"
        p.parent.mkdir(parents=True)
        _resolver_capture(p)
        caps.append((p, 0))
    assert set(testbed.build(caps, {}).source_file) == {"run_a/resolver.pcap", "run_b/resolver.pcap"}
