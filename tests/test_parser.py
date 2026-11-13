"""parser/: CIC pcap reader, features, and the one-call loader, on a hand-built pcap."""

import socket
import struct

import dpkt
import pandas as pd
import pytest

from contracts import validate_queries
from models import m1_features
from parser import cic, features, load


def _dns(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    udp = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
    udp.ulen = len(udp)
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=17, data=udp)
    ip.len = len(ip)
    return bytes(dpkt.ethernet.Ethernet(src=b"\x02" * 6, dst=b"\x04" * 6, type=0x800, data=ip))


def _query(txid: int, name: str, qtype: int = 16) -> bytes:
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
    return struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack(">HH", qtype, 1)


def _reply(query: bytes, rcode: int = 0) -> bytes:
    return query[:2] + struct.pack(">H", 0x8180 | rcode) + query[4:]


def _pcap(path, frames) -> None:
    with open(path, "wb") as f:
        w = dpkt.pcap.Writer(f)
        for ts, buf in frames:
            w.writepkt(buf, ts=ts)


@pytest.fixture
def raw(tmp_path):
    """data/raw/cic layout: one attack capture and one benign capture."""
    exfil = "init.MFRGGZDFMZTWQ2LK.example.com"
    q1, q2 = _query(1, exfil), _query(2, "www.example.com", 1)
    cut = _query(3, "0.abcdefghijklmnopqrstuvwxyz.example.com")[:30]  # snaplen-truncated name
    a, r = "10.0.0.5", "10.0.0.53"
    attack = [
        (100.0, _dns(a, r, 5000, 53, q1)),
        (100.2, _dns(a, r, 5000, 53, q1)),  # retransmission before the reply: kept once
        (100.3, _dns(r, a, 53, 5000, _reply(q1, 3))),
        (101.0, _dns(a, r, 5001, 53, q2)),
        (101.1, _dns(r, a, 53, 5001, _reply(q2))),
        (102.0, _dns(a, r, 5002, 53, cut)),
        (103.0, b"\x00" * 20),  # malformed frame: skipped
    ]
    names = ["host0.example.org", "host1.example.org", "host2.example.org", "2391.wcitianka.com"]  # last: exfil-like
    benign = [(200.0 + i, _dns("10.0.0.6", r, 6000 + i, 53, _query(10 + i, n, 1))) for i, n in enumerate(names)]
    root = tmp_path / "attack_data" / "cic"  # "attack" above raw must not mark benign captures as attacks
    (root / "heavy_attacks").mkdir(parents=True)
    (root / "benign").mkdir()
    _pcap(root / "heavy_attacks" / "a.pcap", attack)
    _pcap(root / "benign" / "b.pcap", benign)
    return root


def test_cic_reader(raw):
    df = cic.build(raw)
    validate_queries(df)
    attack = df[df.source_file.str.endswith("a.pcap")].reset_index(drop=True)
    assert len(attack) == 3  # retransmission and malformed frame dropped
    first = attack.iloc[0]
    assert (first.label, first.tool, first.qtype, first.rcode) == (1, "dnsexfiltrator", "TXT", 3)
    assert first.resp_size > 0
    assert (attack.iloc[1].label, attack.iloc[1].tool) == (0, "benign")  # normal lookup inside an attack pcap
    assert attack.iloc[2].qname_truncated and attack.iloc[2].rcode == -1  # cut name, no reply
    assert set(df.split) == {"train", "test"}
    assert df[df.source_file.str.endswith("b.pcap")].label.sum() == 0
    assert cic.build(raw / "heavy_attacks").label.sum() == 2  # --raw pointed at one attack folder


def test_features_line_up(raw):
    q = cic.build(raw)
    f = features.build(q)
    assert len(f) == len(q) and (f.ts.values == q.ts.values).all()
    assert {"entropy", "n_labels", "h_qpm"} <= set(f.columns)
    assert m1_features.drop_list(f) == m1_features.drop_list(q) != []  # CIC leakage guard still applies


def test_cli_and_load(raw, tmp_path):
    out = tmp_path / "processed" / "cic" / "queries.parquet"
    cic.main(["--raw", str(raw), "--out", str(out)])
    features.main(["--dataset", "cic", "--root", str(out.parent.parent)])
    assert len(pd.read_parquet(out.parent / "features.parquet")) == len(pd.read_parquet(out))
    train, test = load("cic", out.parent.parent)
    assert len(train) + len(test) == len(pd.read_parquet(out))
    assert set(train.split) == {"train"} and set(test.split) == {"test"}
