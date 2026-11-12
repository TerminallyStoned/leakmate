"""Card 7 acceptance tests: the plan is reproducible, every name parses, the sidecar
carries the contract columns, and ``check_benign`` agrees with the card's bar.

All offline — nothing here touches the network or needs the testbed (card 5).
"""

from __future__ import annotations

import json
import random
import time

import pytest
from pathlib import Path

import domains as dom
import generate as gen


POOL = ["example.com", "wikipedia.org", "shopee.sg", "github.com", "amazon.com"]


def make_generator(
    seed: int = 7,
    engines: tuple[str, ...] = ("dns", "cdn", "page", "curl", "apt"),
    edge_hosts: list[str] | None = None,
) -> gen.BenignGenerator:
    return gen.BenignGenerator(
        src_host="benign-01",
        pool=list(POOL),
        rng=random.Random(seed),
        send=False,
        engines=engines,
        edge_hosts=edge_hosts,
    )


def act_many(g: gen.BenignGenerator, n: int) -> list[tuple[str, str, str]]:
    ts = time.time()
    out = []
    for i in range(n):
        for lookup in g.act(ts + i):
            out.append((lookup.engine, lookup.qname, lookup.qtype))
    return out


def test_valid_fqdn_edges() -> None:
    assert dom.is_valid_fqdn("example.com")
    assert dom.is_valid_fqdn("d1f2g3h4j5k6l7.cloudfront.net")
    assert dom.is_valid_fqdn("_dmarc.example.com")
    assert not dom.is_valid_fqdn("no-tld")
    assert not dom.is_valid_fqdn("bad label.com")
    assert not dom.is_valid_fqdn(f"{'a' * 64}.com")
    assert not dom.is_valid_fqdn(f"{'a' * 63}.{'b' * 63}.{'c' * 63}.{'d' * 63}.com")  # 262 > 253
    assert not dom.is_valid_fqdn("")


def test_fallback_pool_is_usable() -> None:
    pool = dom.load_fallback()
    assert len(pool) >= 100
    assert all(dom.is_valid_fqdn(d) for d in pool)


def test_tranco_falls_back_offline(tmp_path: Path) -> None:
    pool = dom.load_top_domains(limit=200, cache_file=tmp_path / "tranco.csv", allow_network=False)
    assert len(pool) >= 100


def test_plan_is_reproducible_with_a_seed() -> None:
    a = act_many(make_generator(seed=42), 400)
    b = act_many(make_generator(seed=42), 400)
    assert a == b
    assert len(a) > 300


def test_extract_edge_hosts_keeps_only_real_looking_edge_names() -> None:
    html = (
        '<img src="https://d1v2h8kf3jx9qm.cloudfront.net/a.webp">'
        '<link href="//a20-1.akamai.net/scripts/b.js">'
        '<script src="https://baseline.apple.com/well-known.txt">'
    )
    assert dom.extract_edge_hosts(html) == {
        "d1v2h8kf3jx9qm.cloudfront.net",
        "a20-1.akamai.net",
    }


def test_cdn_engine_prefers_harvested_hostnames() -> None:
    gen_obj = make_generator(seed=3, engines=("cdn",), edge_hosts=["d1zz.cloudfront.net"])
    names = [lookup.qname for lookup in gen_obj.action_cdn(1_700_000_000.0)]
    assert "d1zz.cloudfront.net" in names
    assert len(names) > 1


def test_cdn_engine_invents_names_without_a_harvest() -> None:
    gen_obj = make_generator(seed=3, engines=("cdn",))
    names = [lookup.qname for _ in range(30) for lookup in gen_obj.action_cdn(1_700_000_000.0)]
    assert all(dom.is_valid_fqdn(name) for name in names)
    assert any(name.endswith(dom.CDN_ZONES[0]) for name in names)


def test_generated_names_all_parse_cleanly() -> None:
    g = make_generator(seed=11)
    rows = act_many(g, 4000)
    assert len(rows) > 3000
    assert g.invalid == 0, "generator produced a name that fails DNS syntax"
    for _, name, _ in rows:
        assert dom.is_valid_fqdn(name), name


def test_cdn_and_cloud_names_are_present() -> None:
    g = make_generator(seed=5)
    rows = [name for _, name, _ in act_many(g, 800)]
    cdn = [n for n in rows if any(n.endswith(zone) for zone in dom.CDN_ZONES)]
    assert len(cdn) >= 20, "CDN/cloud coverage is what stops DNS-BERT false positives"
    assert len({n for n in cdn}) == len(cdn) or len(set(cdn)) > 5


def test_page_views_fan_out_into_many_sublookups() -> None:
    g = make_generator(seed=3, engines=("page",))
    rows = act_many(g, 60)
    assert len(rows) / 60 > 3.0


def test_sidecar_rows_carry_the_contract_columns(tmp_path: Path) -> None:
    out = tmp_path / "benign-01.ndjson"
    rc = gen.main(
        [
            "--src-host",
            "benign-01",
            "--minutes",
            "1",
            "--target-qps",
            "500",
            "--max-rows",
            "250",
            "--engines",
            "dns,cdn",
            "--no-send",
            "--seed",
            "9",
            "--out",
            str(out),
        ]
    )
    assert rc == 0
    lines = [ln for ln in out.read_text(encoding="utf-8").splitlines() if ln]
    assert 200 <= len(lines) <= 260
    row = row_of(lines[0])
    for column in gen.CONTRACT_COLUMNS:
        assert column in row, f"{column} missing from sidecar row"
    assert row["label"] == 0
    assert row["tool"] == "benign"
    assert row["dataset"] == "testbed"
    assert row["throttle"] is False
    assert row["session_id"].startswith("benign-01-")


def test_out_directory_is_named_after_the_host(tmp_path: Path) -> None:
    rc = gen.main(
        ["--src-host", "benign-02", "--minutes", "0.01", "--target-qps", "500", "--max-rows", "20",
         "--no-send", "--engines", "dns", "--out", f"{tmp_path}/"]
    )
    assert rc == 0
    assert (tmp_path / "benign-02.ndjson").is_file()
    assert (tmp_path / "benign-02.summary.json").is_file()


def row_of(line: str) -> dict:
    """Parse one sidecar line; a malformed line must fail the test loudly, not silently."""
    try:
        return json.loads(line)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"sidecar row is not valid JSON: {line[:120]!r}") from exc


def write_sidecar(path: Path, rows: int, hosts: int = 4, span: float = 600.0, cdn_every: int = 6) -> None:
    rng = random.Random(1)
    start = 1_700_000_000.0
    with path.open("w", encoding="utf-8") as fh:
        for i in range(rows):
            host = f"benign-{i % hosts + 1:02d}"
            name = dom.random_cdn_fqdn(rng) if i % cdn_every == 0 else rng.choice(POOL)
            row = {
                "ts": round(start + span * i / max(1, rows - 1), 6),
                "src_host": host,
                "session_id": f"{host}-{i}",
                "qname": name,
                "qtype": "A",
                "resp_size": 128,
                "rcode": "NOERROR",
                "label": 0,
                "tool": "benign",
                "dataset": "testbed",
                "throttle": False,
                "engine": "cdn" if i % cdn_every == 0 else "dns",
            }
            fh.write(json.dumps(row) + "\n")


def test_check_passes_a_card7_sized_run(tmp_path: Path) -> None:
    sidecar = tmp_path / "benign-01.ndjson"
    write_sidecar(sidecar, rows=5001)
    problems, stats = gen_check([sidecar])
    assert problems == [], problems
    assert stats["rows"] == 5001 and stats["qps"] > 8


def test_check_rejects_a_thin_run(tmp_path: Path) -> None:
    sidecar = tmp_path / "benign-01.ndjson"
    write_sidecar(sidecar, rows=200, span=60.0)
    problems, _ = gen_check([sidecar])
    assert any("below the required" in p for p in problems)
    assert any("shorter than" in p for p in problems)


def test_check_flags_rows_that_do_not_parse(tmp_path: Path) -> None:
    sidecar = tmp_path / "benign-01.ndjson"
    write_sidecar(sidecar, rows=5001)
    lines = sidecar.read_text(encoding="utf-8").splitlines()
    bad = row_of(lines[10])
    bad["qname"] = "not a hostname"
    lines[10] = json.dumps(bad)
    sidecar.write_text("\n".join(lines) + "\n", encoding="utf-8")
    problems, _ = gen_check([sidecar])
    assert any("fail DNS syntax" in p for p in problems)


def gen_check(paths: list[Path]):
    import check_benign

    return check_benign.check(paths, min_queries=5000, window_minutes=10.0, min_hosts=2)


def test_no_http_queues_no_web_fetches() -> None:
    """In the lab an HTTP fetch can only fail, so --no-http must not queue one."""
    g = gen.BenignGenerator(
        src_host="benign-01", pool=list(POOL), rng=random.Random(5), send=True, http=False
    )
    list(g.action_curl(1000.0))
    assert g._net.qsize() == 0


def test_no_http_asks_the_resolver_for_tool_traffic() -> None:
    """Without a route the tool never resolves anything, so dig does it instead."""
    g = gen.BenignGenerator(
        src_host="benign-01", pool=list(POOL), rng=random.Random(5), send=True, http=False
    )
    asked: list[tuple[str, str]] = []

    def fake_dig(name: str, qtype: str = "A"):
        asked.append((name, qtype))
        return 61, "NOERROR"

    g.dig = fake_dig  # type: ignore[method-assign]
    rows = list(g.action_curl(1000.0))
    assert asked, "curl traffic produced no resolver lookup"
    assert all(r.resp_size == 61 for r in rows if r.qtype == "A" and r.rcode)
    assert rows, "curl action emitted nothing"


def test_http_mode_leaves_tool_lookups_to_the_tool() -> None:
    g = make_generator()
    asked: list[str] = []
    g.dig = lambda name, qtype="A": (asked.append(name) or (None, None))  # type: ignore[assignment]
    list(g.action_curl(1000.0))
    assert asked == [], "the tool itself resolves; dig must stay out of it"


def test_edge_host_list_round_trip(tmp_path: Path) -> None:
    path = dom.save_edge_hosts(["A1B2.cloudfront.net", "d3.azureedge.net"], tmp_path / "edge_hosts.txt")
    assert dom.load_edge_hosts(path) == ["a1b2.cloudfront.net", "d3.azureedge.net"]
    assert dom.load_edge_hosts(tmp_path / "absent.txt") == []


def test_offline_run_reuses_the_harvested_list(tmp_path: Path) -> None:
    """A lab run cannot harvest, so --edge-hosts-file is where its CDN names come from."""
    edge_file = dom.save_edge_hosts(["px9f3a.cloudfront.net", "t7k2.akamaized.net"], tmp_path / "edge_hosts.txt")
    sidecar = tmp_path / "benign-01.ndjson"
    rc = gen.main(
        [
            "--no-send",
            "--engines", "cdn",
            "--max-rows", "40",
            "--out", str(sidecar),
            "--edge-hosts-file", str(edge_file),
        ]
    )
    assert rc == 0
    names = {json.loads(line)["qname"] for line in sidecar.read_text(encoding="utf-8").splitlines()}
    assert names & {"px9f3a.cloudfront.net", "t7k2.akamaized.net"}


def test_testbed_compose_keeps_card5_services_and_gates_benign() -> None:
    """Adding benign must not change what `docker compose up -d` in testbed/ starts."""
    yaml = pytest.importorskip("yaml")
    compose = Path(__file__).resolve().parents[2] / "docker-compose.yml"
    spec = yaml.safe_load(compose.read_text(encoding="utf-8"))
    assert set(spec["services"]) == {"attacker-ns", "resolver", "victim", "benign"}
    benign = spec["services"]["benign"]
    assert benign["profiles"] == ["benign"], "benign must stay behind a profile"
    assert benign["networks"] == {"lab": None}, "no static IP, or --scale cannot run replicas"
    assert "172.28.0.2" in benign["dns"][0], "dns must default to the card-5 resolver"
    assert "--no-http" in benign["command"], "the lab has no route for web fetches"
    # rsplit: the host side of the output mount contains ":-" from the compose default.
    assert {v.rsplit(":", 1)[1] for v in benign["volumes"]} >= {"/app/data/external", "/out"}


def test_src_host_auto_never_names_the_sidecar_auto(tmp_path: Path) -> None:
    """Two replicas both labelled "auto" shared one file and interleaved JSON."""
    assert gen.main(["--src-host", "auto", "--no-send", "--minutes", "0.02",
                     "--target-qps", "40", "--out", f"{tmp_path}/"]) == 0
    written = [q.name for q in tmp_path.glob("*.ndjson")]
    assert len(written) == 1 and written[0] != "auto.ndjson", written


def test_checker_reports_malformed_lines(tmp_path: Path) -> None:
    import check_benign

    path = tmp_path / "benign-01.ndjson"
    write_sidecar(path, rows=400, hosts=1, span=60.0)
    lines = path.read_text().splitlines()
    # What a second writer truncating mid-record looks like.
    path.write_text("\n".join(lines[:-1]) + "\n" + lines[-1][:40] + "\n")
    problems, _ = check_benign.check([path], min_queries=100, window_minutes=1.0, min_hosts=1)
    assert any("malformed" in q for q in problems), problems


def test_ipv4_helper() -> None:
    assert gen._ipv4("172.28.0.4")
    assert not gen._ipv4("::1")
    assert not gen._ipv4(None)
    assert not gen._ipv4("hermes-vm")
