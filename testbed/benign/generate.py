#!/usr/bin/env python3
"""Benign traffic generator for the ICT3214 DNS-exfiltration testbed (Trello card 7).

Produces realistic *benign* DNS traffic — scripted Tranco lookups at randomised
intervals, real ``curl``/``apt`` fetches, headless-browser page views, and hashed CDN /
cloud hostnames — from several simulated hosts so per-host window features have variety.

Every lookup is appended to an NDJSON (or CSV) sidecar whose column names match the
shared query contract (``ts, src_host, session_id, qname, qtype, resp_size, rcode,
label, tool, dataset, throttle``) plus two extras the parser can ignore
(``engine``, and the raw ``qname`` case). ``resp_size``/``rcode`` are filled for lookups
we issue ourselves with ``dig``; for traffic caused by real tools (curl/apt/browser) the
capture at the resolver is the source of truth, so those columns stay empty.

Run it through ``run_benign.sh`` (that is the documented entry point); ``--no-send``
plans traffic without touching the network, which is what the tests use.
"""

from __future__ import annotations

import argparse
import contextlib
import csv
import json
import logging
import os
import random
import pathlib
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import queue
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Generator, Iterator, TextIO

# Script-style sibling import: this module is run as a program (`python3 generate.py`) and
# imported by the tests, so the package-relative form is not available.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import domains as dom  # noqa: E402  (sibling module, script-style import)

log = logging.getLogger("benign")

CONTRACT_COLUMNS = (
    "ts",
    "src_host",
    "session_id",
    "qname",
    "qtype",
    "resp_size",
    "rcode",
    "label",
    "tool",
    "dataset",
    "throttle",
)
ENGINE_COLUMNS = ("engine",)

APT_HOSTS = (
    "archive.ubuntu.com",
    "security.ubuntu.com",
    "archive.debian.org",
    "security.debian.org",
)
APT_PACKAGES = ("curl", "vim", "git", "python3-requests", "htop", "jq", "tree", "wget")

_STATUS_RE = re.compile(r"status: (\w+), id:")
_SIZE_RE = re.compile(r"MSG SIZE\s+rcvd:\s*(\d+)")

_STOPPED = False


def _ipv4(value: str | None) -> bool:
    return bool(value) and bool(re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", value))


def auto_host() -> str:
    """This machine's own IPv4, so src_host matches the pcap source address.

    Containers on the isolated lab network have no default route, so a UDP probe would
    fail; gethostbyname(hostname) does not need one and returns the eth0 address docker
    wrote into /etc/hosts.
    """
    name = socket.gethostname()
    try:
        ip = socket.gethostbyname(name)
    except OSError:
        ip = None
    if _ipv4(ip) and not ip.startswith("127."):
        return ip
    # Docker writes the container *id* into /etc/hosts, so the compose hostname does not
    # resolve; the address on that line is still the one the capture sees.
    try:
        hosts_txt = pathlib.Path("/etc/hosts").read_text(encoding="utf-8")
    except OSError:
        hosts_txt = ""
    for line in hosts_txt.splitlines():
        fields = line.split()
        if len(fields) >= 2 and _ipv4(fields[0]) and not fields[0].startswith("127."):
            return fields[0]
    return name


def _handle_signal(signum: int, _frame: object) -> None:  # pragma: no cover - signal path
    global _STOPPED
    _STOPPED = True
    log.info("received signal %d, finishing current action", signum)


@dataclass(slots=True)
class Lookup:
    """One emitted DNS query, in contract column order."""

    ts: float
    src_host: str
    session_id: str
    qname: str
    qtype: str
    engine: str
    resp_size: int | None = None
    rcode: str | None = None

    def to_row(self, dataset: str, throttle: bool) -> dict[str, object]:
        return {
            "ts": self.ts,
            "src_host": self.src_host,
            "session_id": self.session_id,
            "qname": self.qname,
            "qtype": self.qtype,
            "resp_size": self.resp_size,
            "rcode": self.rcode,
            "label": 0,
            "tool": "benign",
            "dataset": dataset,
            "throttle": throttle,
            "engine": self.engine,
        }


@dataclass(slots=True)
class EngineMix:
    """Action weights and the expected number of lookups each action produces."""

    weights: dict[str, float] = field(default_factory=dict)
    fanout: dict[str, float] = field(default_factory=dict)

    def pick(self, rng: random.Random) -> str:
        return rng.choices(list(self.weights), weights=list(self.weights.values()), k=1)[0]

    @property
    def rows_per_action(self) -> float:
        total_w = sum(self.weights.values()) or 1.0
        return sum(w * self.fanout.get(name, 1.0) for name, w in self.weights.items()) / total_w


def default_mix(engines: tuple[str, ...]) -> EngineMix:
    all_weights = {"dns": 0.40, "cdn": 0.18, "page": 0.22, "curl": 0.15, "apt": 0.05}
    all_fanout = {"dns": 1.25, "cdn": 2.0, "page": 7.0, "curl": 1.4, "apt": 2.0}
    weights = {name: all_weights[name] for name in engines if name in all_weights}
    if not weights:
        raise SystemExit(f"no usable engines in {engines}")
    return EngineMix(weights=weights, fanout=all_fanout)


class Sidecar:
    """Append-only NDJSON/CSV writer for contract rows."""

    def __init__(self, path: Path, fmt: str = "ndjson", dataset: str = "testbed", throttle: bool = False):
        self.path = path
        self.fmt = fmt
        self.dataset = dataset
        self.throttle = throttle
        self.rows = 0
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._fh: TextIO = path.open("w", encoding="utf-8", newline="")
        except OSError as exc:
            raise SystemExit(f"cannot write sidecar {path}: {exc}") from exc
        self._writer: csv.DictWriter | None = None
        if fmt == "csv":
            self._writer = csv.DictWriter(self._fh, fieldnames=list(CONTRACT_COLUMNS) + list(ENGINE_COLUMNS))
            self._writer.writeheader()

    def write(self, lookup: Lookup) -> None:
        row = lookup.to_row(self.dataset, self.throttle)
        if self._writer is not None:
            self._writer.writerow(row)
        else:
            self._fh.write(json.dumps(row, separators=(",", ":")) + "\n")
        self.rows += 1
        if self.rows % 200 == 0:
            self._fh.flush()

    def close(self) -> None:
        self._fh.flush()
        self._fh.close()


class BenignGenerator:
    """Emits benign lookups for exactly one source host."""

    def __init__(
        self,
        src_host: str,
        pool: list[str],
        rng: random.Random,
        *,
        resolver: str | None = None,
        send: bool = True,
        engines: tuple[str, ...] = ("dns", "cdn", "page", "curl", "apt"),
        browser: str | None = None,
        browser_min_interval: float = 30.0,
        apt_min_interval: float = 300.0,
        fetch_timeout: float = 3.0,
        http: bool = True,
        dataset: str = "testbed",
        throttle: bool = False,
        edge_hosts: list[str] | None = None,
    ):
        self.src_host = src_host
        self.pool = pool or dom.load_fallback()
        self.rng = rng
        self.resolver = resolver
        self.send = send
        self.engines = engines
        self.browser_url = browser
        self.browser_min_interval = browser_min_interval
        self.apt_min_interval = apt_min_interval
        self.fetch_timeout = fetch_timeout
        # False inside the testbed: `lab` is internal, so an HTTP fetch only fails slowly.
        # Lookups are still issued with dig, which the resolver does forward.
        self.http = http
        self._net: queue.Queue[str | None] = queue.Queue()
        self._net_thread: threading.Thread | None = None
        self.dataset = dataset
        self.throttle = throttle
        # Real hashed edge names harvested from page HTML: invented ones answer NXDOMAIN,
        # and rcode is a genuine tunnel signal, so the benign class must not pollute it.
        self.edge_hosts = list(edge_hosts) if edge_hosts else []
        self.mix = default_mix(engines)
        self.seq = 0
        self.errors = 0
        self.invalid = 0
        self._dig = shutil.which("dig")
        self._apt_last = -self.apt_min_interval
        self._browser_last = -self.browser_min_interval
        self._pw = None
        self._pw_page = None
        self._by_engine: dict[str, int] = {}

    # ---------------------------------------------------------------- utilities

    def _record(self, qname: str, qtype: str, engine: str, ts: float, resp_size: int | None = None, rcode: str | None = None) -> Lookup:
        name = qname.rstrip(".").lower()
        if not dom.is_valid_fqdn(name):
            self.invalid += 1
            log.debug("dropping invalid generated name %r", qname)
            name = ""
        self.seq += 1
        self._by_engine[engine] = self._by_engine.get(engine, 0) + 1
        return Lookup(
            ts=round(ts, 6),
            src_host=self.src_host,
            session_id=f"{self.src_host}-{self.seq}",
            qname=name,
            qtype=qtype,
            engine=engine,
            resp_size=resp_size,
            rcode=rcode,
        )

    def dig(self, qname: str, qtype: str = "A") -> tuple[int | None, str | None]:
        """Resolve *qname* with dig and return (response size bytes, rcode)."""
        if not (self.send and self._dig):
            return None, None
        cmd = [self._dig, "+noall", "+comments", "+stats", "+time=1", "+tries=1"]
        if self.resolver:
            cmd.append(f"@{self.resolver}")
        cmd += [qname, qtype]
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=8.0).stdout
        except (subprocess.TimeoutExpired, OSError):
            self.errors += 1
            return None, None
        status = _STATUS_RE.search(out)
        size = _SIZE_RE.search(out)
        # _SIZE_RE only ever matches \d+, so int() cannot raise here.
        return (
            int(size.group(1)) if size else None,  # pi-lens-ignore: unchecked-numeric-parse-python
            status.group(1) if status else None,
        )

    def _tool_lookup(self, name: str, qtype: str = "A") -> tuple[int | None, str | None]:
        """Resolve a host a real tool would have resolved.

        With a route, the tool's own stack does the lookup and the capture sees it, so we
        record nothing here. Without one (testbed `--no-http`) the tool never asks, so we
        ask the resolver ourselves rather than log a query that never happened.
        """
        return () if self.http else self.dig(name, qtype)

    def http_get(self, url: str) -> None:
        """Queue a fetch so the tool chain performs its own resolver lookups.

        Handled on a background thread: a slow or dead web server must not stall the
        paced lookup loop, and it is the DNS traffic the resolver capture records.
        """
        if self.send and self.http:
            self._net.put(url)

    def _drain_net(self) -> None:
        while True:
            url = self._net.get()
            if url is None:
                return
            req = urllib.request.Request(url, headers={"User-Agent": dom.USER_AGENT, "Accept": "*/*"})
            try:
                with contextlib.closing(urllib.request.urlopen(req, timeout=self.fetch_timeout)) as resp:
                    resp.read(2048)
            except Exception:  # a dead page is normal browsing noise, not a generator error
                self.errors += 1
            finally:
                self._net.task_done()

    def _page(self):
        """Lazy Playwright page; None when the optional dependency is absent."""
        if self._pw_page is not None or not self.send or not self.http:
            return self._pw_page
        try:
            from playwright.sync_api import sync_playwright  # type: ignore[import-not-found]
        except Exception:
            log.info("Playwright unavailable; page views fall back to scripted lookups")
            self._pw_page = False
            return None
        try:
            self._pw = sync_playwright().start()
            launcher = getattr(self._pw.chromium, "connect_over_cdp") if self.browser_url else None
            if launcher:
                browser = launcher(self.browser_url)
                self._pw_page = (browser.contexts[0] if browser.contexts else browser.new_context()).new_page()
            else:
                self._pw = self._pw.chromium.launch()
                self._pw_page = self._pw.new_page()
        except Exception as exc:
            log.warning("browser start failed (%s); using scripted page views", exc)
            self._pw_page = False
        return self._pw_page or None

    def close(self) -> None:
        if self._pw is not None and not isinstance(self._pw_page, bool):
            with contextlib.suppress(Exception):
                self._pw.stop()

    @property
    def counts(self) -> dict[str, int]:
        return dict(self._by_engine)

    # ----------------------------------------------------------------- actions

    def act(self, ts: float) -> Generator[Lookup, None, None]:
        """Emit the lookups for one random benign action."""
        mix = self.mix
        engine = mix.pick(self.rng)
        if engine == "dns":
            yield from self.action_dns(ts)
        elif engine == "cdn":
            yield from self.action_cdn(ts)
        elif engine == "page":
            yield from self.action_page(ts)
        elif engine == "curl":
            yield from self.action_curl(ts)
        else:
            yield from self.action_apt(ts)

    def action_dns(self, ts: float) -> Generator[Lookup, None, None]:
        """Scripted lookup of a top-sites domain at whatever type a client asks for."""
        domain = self.rng.choice(self.pool)
        roll = self.rng.random()
        if roll < 0.62:
            pairs = [(domain, "A")]
        elif roll < 0.85:
            pairs = [(f"www.{domain}", "A"), (domain, "AAAA")]
        elif roll < 0.93:
            pairs = [(domain, "AAAA")]
        else:
            pairs = [(domain, self.rng.choice(("MX", "NS", "SOA", "TXT")))]
        for name, qtype in pairs:
            size, rcode = self.dig(name, qtype)
            yield self._record(name, qtype, "dns", ts, size, rcode)
            if self.rng.random() < 0.25:  # retry / second resolver in a client stub
                ts2 = ts + self.rng.uniform(0.01, 0.2)
                name2 = name if self.rng.random() < 0.5 else f"{name}.{self.rng.choice(('internal', 'lan', 'home.arpa'))}"
                yield self._record(name2, "A", "dns", ts2, *self.dig(name2, "A"))

    def action_cdn(self, ts: float) -> Generator[Lookup, None, None]:
        """Hashed edge hostnames — the high-entropy-benign class models must learn."""
        for _ in range(self.rng.randint(1, 4)):
            name = self.rng.choice(self.edge_hosts) if self.edge_hosts and self.rng.random() < 0.85 else dom.random_cdn_fqdn(self.rng)
            qtype = "A" if self.rng.random() < 0.8 else "AAAA"
            yield self._record(name, qtype, "cdn", ts + self.rng.uniform(0, 0.4), *self.dig(name, qtype))

    def action_page(self, ts: float) -> Generator[Lookup, None, None]:
        """One page view: publisher + assets + ads, i.e. many sub-lookups."""
        domain = self.rng.choice(self.pool)
        hosts = dom.page_hosts(self.rng, domain, self.pool, edge_hosts=self.edge_hosts)
        # One navigation per browser_min_interval: a real page load blocks this loop for
        # seconds, so the rest of the page views stay scripted to keep the lookup rate.
        page = self._page() if ts - self._browser_last >= self.browser_min_interval else None
        if page is not None:
            self._browser_last = ts
            with contextlib.suppress(Exception):
                page.goto(f"https://{hosts[0]}/", timeout=5_000, wait_until="commit")
            # The browser itself resolved everything; log the names we expected to see.
            for host in hosts:
                yield self._record(host, "A", "browser", ts + self.rng.uniform(0, 1.5))
            return
        for host in hosts:
            yield self._record(host, "A", "page", ts + self.rng.uniform(0, 1.5), *self.dig(host, "A"))
            if self.rng.random() < 0.3:
                yield self._record(host, "AAAA", "page", ts + self.rng.uniform(0, 1.5), *self.dig(host, "AAAA"))

    def action_curl(self, ts: float) -> Generator[Lookup, None, None]:
        """Plain tool traffic: curl a page, sometimes a CDN asset too."""
        domain = self.rng.choice(self.pool)
        url = f"https://{domain}/"
        yield self._record(domain, "A", "curl", ts, *self._tool_lookup(domain, "A"))
        self.http_get(url)
        if self.rng.random() < 0.5:
            cdn = dom.random_cdn_fqdn(self.rng)
            yield self._record(cdn, "A", "curl", ts + self.rng.uniform(0.1, 0.8), *self._tool_lookup(cdn, "A"))
            self.http_get(f"https://{cdn}/assets/app.js")
        if self.rng.random() < 0.2:
            typo_host = self.rng.choice(self.pool)
            name = f"api.{typo_host}" if self.rng.random() < 0.5 else f"{typo_host.split('.')[0]}.io"
            yield self._record(name, "A", "curl", ts + self.rng.uniform(1, 3), *self.dig(name, "A"))

    def action_apt(self, ts: float) -> Generator[Lookup, None, None]:
        """Package-manager burst, at most once per ``apt_min_interval`` seconds."""
        if ts - self._apt_last < self.apt_min_interval:
            yield from self.action_dns(ts)
            return
        self._apt_last = ts
        for host in self.rng.sample(APT_HOSTS, k=self.rng.randint(1, len(APT_HOSTS))):
            yield self._record(host, "A", "apt", ts, *self.dig(host, "A"))
        pkg = self.rng.choice(APT_PACKAGES)
        if self.send and self.http and shutil.which("apt-get"):
            cmds = (
                ["apt-get", "update", "-qq"],
                ["apt-get", "install", "-y", "-qq", "--no-install-recommends", "--download-only", pkg],
            )
            for cmd in cmds:
                try:
                    subprocess.run(cmd, capture_output=True, text=True, timeout=180.0)
                except (subprocess.TimeoutExpired, OSError):
                    self.errors += 1
        elif self.send and self.http:  # no apt in this image: hit the mirrors over HTTP instead
            host = self.rng.choice(APT_HOSTS)
            self.http_get(f"http://{host}/")
            yield self._record(host, "A", "apt", ts + self.rng.uniform(0.2, 1.0))

    # ------------------------------------------------------------------ driver

    def run(self, out: Sidecar, minutes: float, target_qps: float, hosts: int, max_rows: int | None = None) -> dict[str, object]:
        """Generate traffic for ``minutes`` minutes aiming at ``target_qps`` total lookups/s.

        ``rate`` is *actions* per second for this host; an action averages
        ``mix.rows_per_action`` lookups (a page view is several), so the emitted lookup
        rate is ``rate * rows_per_action * hosts`` ≈ ``target_qps``.
        """
        rate = max(0.02, target_qps / (max(1, hosts) * self.mix.rows_per_action))
        end = time.time() + minutes * 60.0
        started = time.time()
        rows = 0
        pauses = 0
        while time.time() < end and not _STOPPED:
            if max_rows is not None and rows >= max_rows:
                break
            now = time.time()
            for lookup in self.act(now):
                if lookup.qname:
                    out.write(lookup)
                    rows += 1
            if self.rng.random() < 0.02:  # someone stopped reading
                pause = self.rng.uniform(2.0, 12.0)
                end += pause
                pauses += 1
                time.sleep(pause)
            time.sleep(max(0.005, self.rng.expovariate(rate)))
        elapsed = time.time() - started
        return {
            "src_host": self.src_host,
            "rows": rows,
            "elapsed_s": round(elapsed, 3),
            "qps_achieved": round(rows / elapsed, 3) if elapsed > 0 else 0.0,
            "by_engine": self.counts,
            "pauses": pauses,
            "errors": self.errors,
            "invalid_names": self.invalid,
            "engines": list(self.engines),
        }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument(
        "--src-host",
        default="auto",
        help="host label written to the sidecar; \"auto\" is this machine's own IP, the address "
        "the resolver capture sees (fallback: $HOSTNAME)",
    )
    p.add_argument("--minutes", type=float, default=10.0, help="run duration in minutes (fractions allowed)")
    p.add_argument("--target-qps", type=float, default=10.0, help="approximate total lookups/s across all hosts")
    p.add_argument("--hosts", type=int, default=1, help="host count used only to divide --target-qps")
    p.add_argument("--resolver", default=os.environ.get("RESOLVER_IP") or None, help="testbed resolver to query (default: /etc/resolv.conf)")
    p.add_argument("--out", help="sidecar file, or a directory (trailing /) to write <src-host>.ndjson into")
    p.add_argument("--format", choices=("ndjson", "csv"), default="ndjson")
    p.add_argument("--engines", default="dns,cdn,page,curl,apt", help="comma list of dns,cdn,page,curl,apt")
    p.add_argument("--tranco-limit", type=int, default=1000, help="how many top-sites to draw from")
    p.add_argument("--browser", default=os.environ.get("BROWSER_CDP") or None, help="CDP endpoint of a shared headless browser")
    p.add_argument("--fetch-timeout", type=float, default=3.0, help="seconds to wait on a queued web fetch")
    p.add_argument("--browser-interval", type=float, default=30.0, help="seconds between real headless-browser page loads")
    p.add_argument("--harvest-pages", type=int, default=40, help="top-site pages scanned for real CDN hostnames (0 disables)")
    p.add_argument("--seed", type=int, default=None, help="RNG seed for a reproducible plan")
    p.add_argument("--max-rows", type=int, default=None, help="stop after this many rows (smoke tests)")
    p.add_argument("--dataset", default="testbed", help="value of the dataset contract column")
    p.add_argument("--throttle", action="store_true", help="mark rows as a throttled low-and-slow run (E5)")
    p.add_argument("--no-send", action="store_true", help="plan lookups without touching the network")
    p.add_argument(
        "--edge-hosts-file",
        default=str(dom.EDGE_HOSTS_FILE),
        help="harvested edge names to use when this run cannot fetch pages (testbed); written by --prepare",
    )
    p.add_argument(
        "--prepare",
        action="store_true",
        help="with internet: refresh the Tranco cache and the edge-name list, then exit",
    )
    p.add_argument(
        "--no-http",
        action="store_true",
        help="issue every lookup via dig and skip web fetches (testbed `lab` has no route out)",
    )
    p.add_argument("--summary", type=Path, default=None, help="write run summary JSON here")
    p.add_argument("--verbose", "-v", action="store_true")
    return p.parse_args(argv)


def _resolve_out(args: argparse.Namespace) -> Path:
    """``--out`` may be a file or a directory; scaled containers pass a shared directory."""
    raw = args.out if isinstance(args.out, str) else str(args.out)
    out = Path(raw)
    if out.is_dir() or raw.endswith(("/", os.sep)):
        out.mkdir(parents=True, exist_ok=True)
        suffix = ".csv" if args.format == "csv" else ".ndjson"
        out = out / f"{args.src_host}{suffix}"
        if args.summary is None:
            args.summary = out.with_suffix(".summary.json")
    return out


def _prepare(args: argparse.Namespace) -> int:
    """Refresh the two internet-only inputs a lab run needs, then exit.

    `lab` is internal: true, so a benign container can neither download Tranco nor fetch
    pages to harvest edge names from. Both are cached under data/external/ (gitignored)
    and bind-mounted into the containers instead.
    """
    out = {"tranco": None, "edge_names": 0}
    pool = dom.load_top_domains(limit=max(args.tranco_limit, 5000))
    out["tranco"] = len(pool)
    hosts = dom.harvest_edge_hosts(pool, max_pages=max(args.harvest_pages, 40))
    if hosts:
        out["edge_names"] = len(hosts)
        out["edge_file"] = str(dom.save_edge_hosts(hosts))
    print(json.dumps(out, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    if not args.prepare and not args.out:
        raise SystemExit("error: --out is required unless --prepare is given")

    # Resolve before --out is derived from it: two replicas both labelled "auto" would
    # otherwise share one sidecar and interleave their JSON lines.
    if args.src_host == "auto":
        args.src_host = auto_host()

    engines = tuple(e.strip() for e in args.engines.split(",") if e.strip())
    rng = random.Random(args.seed)
    online = not (args.no_send or args.no_http)
    if args.prepare:
        return _prepare(args)

    pool = dom.load_top_domains(limit=args.tranco_limit, allow_network=online)
    edge_hosts: list[str] = []
    if online and args.harvest_pages > 0 and "cdn" in engines:
        edge_hosts = dom.harvest_edge_hosts(pool, max_pages=args.harvest_pages)
        log.info("harvested %d real hashed edge hostnames from page HTML", len(edge_hosts))
    elif args.harvest_pages > 0:
        # Inside the lab there is no route to harvest with, so reuse the host's list.
        edge_hosts = dom.load_edge_hosts(args.edge_hosts_file)
        if edge_hosts:
            log.info("loaded %d harvested edge names from %s", len(edge_hosts), args.edge_hosts_file)
    log.info("%d candidate domains, engines=%s, resolver=%s, send=%s", len(pool), ",".join(engines), args.resolver or "system", not args.no_send)

    gen = BenignGenerator(
        src_host=args.src_host,
        pool=pool,
        rng=rng,
        resolver=args.resolver,
        send=not args.no_send,
        engines=engines,
        browser=args.browser,
        browser_min_interval=args.browser_interval,
        fetch_timeout=args.fetch_timeout,
        http=not (args.no_http or args.no_send),
        dataset=args.dataset,
        throttle=args.throttle,
        edge_hosts=edge_hosts,
    )
    out_path = _resolve_out(args)
    out = Sidecar(out_path, fmt=args.format, dataset=args.dataset, throttle=args.throttle)
    try:
        summary = gen.run(out, minutes=args.minutes, target_qps=args.target_qps, hosts=args.hosts, max_rows=args.max_rows)
    finally:
        out.close()
        gen.close()
    summary["out"] = str(out_path)
    summary["resolver"] = args.resolver
    summary["harvested_edge_names"] = len(gen.edge_hosts)
    summary["seed"] = args.seed
    print(json.dumps(summary, indent=2, sort_keys=True))
    if args.summary:
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        args.summary.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
