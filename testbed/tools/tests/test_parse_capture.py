"""Offline tests for scripts/parse_capture.py: synthetic pcaps, no docker, no network.

Run from the repo root:  python3 -m pytest testbed/tools/tests -q
"""

from __future__ import annotations

import socket
import struct
import sys
from pathlib import Path

import dpkt
import dpkt.dns as dns
import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

import parse_capture as pc  # noqa: E402

QUERY_ID = 0x1234


def _frame(q: str, *, reply: bool = False, rcode: int = 0, src: str, dst: str) -> bytes:
    msg = dns.DNS()
    msg.id = QUERY_ID
    msg.qr = 1 if reply else 0  # decoded 0/1 field, not the 0x8000 header bit
    msg.qd = [dns.DNS.Q(name=q, type=dns.DNS_TXT, cls=dns.DNS_IN)]
    if reply:
        msg.rcode = rcode
    udp = dpkt.udp.UDP(sport=53 if reply else 40000, dport=53 if not reply else 53, data=msg.pack())
    udp.ul = len(udp)
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=17, data=udp)
    ip.len = len(ip)
    return bytes(dpkt.ethernet.Ethernet(dst=b"\x02\x00\x00\x00\x00\x01", src=b"\x02\x00\x00\x00\x00\x02", type=0x800, data=ip))


def _write_pcap(path: Path, frames: list[tuple[float, bytes]]) -> None:
    path.write_bytes(b"")
    with path.open("wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))  # classic pcap, Ethernet
        for ts, buf in frames:
            fh.write(struct.pack("<IIII", int(ts), int(ts % 1 * 1e6), len(buf), len(buf)))
            fh.write(buf)


def test_query_reply_pair_becomes_one_contract_row(tmp_path: Path) -> None:
    pcap = tmp_path / "cap.pcap"
    name = "0.abcdefghijklmnop.exfil.tunnel.test"
    _write_pcap(
        pcap,
        [
            (1000.0, _frame(name, src="172.28.0.43", dst="172.28.0.41")),
            (1000.05, _frame(name, reply=True, rcode=0, src="172.28.0.41", dst="172.28.0.43")),
        ],
    )
    stats: dict[str, int] = {}
    rows = pc.parse_pcap(pcap, {"172.28.0.43": "dnsexfiltrator"}, "testbed", "5qps", stats)
    assert len(rows) == 1, rows
    row = rows[0]
    assert row["qname"] == name
    assert row["qtype"] == "TXT"
    assert row["rcode"] == "NOERROR"
    assert row["label"] == 1 and row["tool"] == "dnsexfiltrator"
    assert row["src_host"] == "172.28.0.43"
    assert row["dataset"] == "testbed" and row["throttle"] == "5qps"
    assert row["resp_size"] and row["resp_size"] > 0
    assert list(row) == list(pc.COLUMNS), "row must keep the CONTRACTS column order"
    assert stats.get("queries") == 1 and not stats.get("truncated")


def test_unmapped_address_is_not_labelled_tunnel(tmp_path: Path) -> None:
    pcap = tmp_path / "cap.pcap"
    _write_pcap(pcap, [(1000.0, _frame("google.com", src="172.28.0.10", dst="172.28.0.2"))])
    rows = pc.parse_pcap(pcap, dict(pc.LAB_IPS), "testbed", "")
    assert len(rows) == 1
    assert rows[0]["label"] == 0 and rows[0]["tool"] == "benign"


def test_query_without_reply_keeps_row_and_reports_null(tmp_path: Path) -> None:
    pcap = tmp_path / "cap.pcap"
    _write_pcap(pcap, [(1000.0, _frame("1.aaaa.exfil.tunnel.test", src="172.28.0.43", dst="172.28.0.41"))])
    rows = pc.parse_pcap(pcap, {"172.28.0.43": "dnsexfiltrator"}, "testbed", "")
    assert rows[0]["resp_size"] is None and rows[0]["rcode"] is None


def test_torn_trailing_record_is_dropped_not_fatal(tmp_path: Path, capsys) -> None:
    pcap = tmp_path / "cap.pcap"
    good = _frame("2.aaaa.exfil.tunnel.test", src="172.28.0.43", dst="172.28.0.41")
    _write_pcap(pcap, [(1000.0, good)])
    with pcap.open("ab") as fh:  # what a SIGTERM'd tcpdump leaves behind
        fh.write(struct.pack("<IIII", 1001, 0, 40, 40))
    stats: dict[str, int] = {}
    rows = pc.parse_pcap(pcap, {"172.28.0.43": "dnsexfiltrator"}, "testbed", "", stats)
    assert len(rows) == 1
    assert "partial record" in capsys.readouterr().err


def test_eight_bit_qname_is_kept_not_counted_as_truncated(tmp_path: Path) -> None:
    """iodine's Base128 labels are not UTF-8; dpkt raises on them and the row was lost."""
    pcap = tmp_path / "cap.pcap"
    good = _frame("x" * 8 + ".i.tunnel.test", src="172.28.0.30", dst="172.28.0.2")
    raw = good.replace(b"x" * 8, b"0qc\xca\xbe\xeeY\xd6")  # same length, so lengths/offsets hold
    _write_pcap(pcap, [(1000.0, raw)])
    stats: dict[str, int] = {}
    rows = pc.parse_pcap(pcap, {"172.28.0.30": "iodine"}, "testbed", "", stats)
    assert len(rows) == 1 and not stats.get("truncated")
    assert rows[0]["qname"] == b"0qc\xca\xbe\xeey\xd6".decode("latin-1") + ".i.tunnel.test"
    assert rows[0]["tool"] == "iodine" and rows[0]["label"] == 1


def test_not_a_pcap_is_a_clear_error(tmp_path: Path) -> None:
    bad = tmp_path / "cap.pcap"
    bad.write_bytes(b"pcapng" + b"\x00" * 40)
    with pytest.raises(SystemExit, match="classic pcap magic"):
        pc.parse_pcap(bad, {}, "testbed", "")
