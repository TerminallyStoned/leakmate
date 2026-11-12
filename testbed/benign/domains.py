"""Where benign hostnames come from: Tranco top-sites, CDN/cloud zones, offline fallback.

Tranco is fetched at run time and cached under ``data/external/`` so the list is never
committed (redistribution terms stay untouched). When the network is unavailable the
bundled ``fallback_domains.txt`` is used instead, which keeps ``--no-send`` runs and the
unit tests working offline.
"""

from __future__ import annotations

import csv
import io
import logging
import random
import re
import urllib.request
import zipfile
from collections.abc import Sequence
from pathlib import Path

log = logging.getLogger(__name__)

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
FALLBACK_FILE = HERE / "fallback_domains.txt"
DEFAULT_CACHE = REPO_ROOT / "data" / "external" / "tranco"

# Tranco only serves one file, the million-domain list, as a zip (~10 MB). Smaller
# requests take that many rows from the top of it.
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"

# Public CDN / cloud edges that legitimately serve hash-like hostnames. Deliberately
# included in benign traffic: the proposal names them as the fix for DNS-BERT false
# positives on high-entropy labels.
CDN_ZONES: tuple[str, ...] = (
    "cloudfront.net",
    "d1m1uqzu43r0nx.cloudfront.net",
    "akamaized.net",
    "akeyours15.me",
    "edgesuite.net",
    "edgekey.net",
    "azureedge.net",
    "fastly.net",
    "cdn77.org",
    "cdnbuild.net",
    "gcdn.co",
    "cloudflare.net",
    "blob.core.windows.net",
    "s3.amazonaws.com",
    "storage.googleapis.com",
    "cdn77.securityaws.com",
)

# Third parties a real page pulls in besides the publisher itself.
THIRD_PARTY_ZONES: tuple[str, ...] = (
    "google-analytics.com",
    "googletagmanager.com",
    "doubleclick.net",
    "fonts.gstatic.com",
    "cdn.jsdelivr.net",
    "ajax.googleapis.com",
    "unpkg.com",
    "cloudflare.com",
)

_HEX = "0123456789abcdef"
_B32 = "abcdefghijklmnopqrstuvwxyz234567"

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)

# Asset hostnames actually present in page HTML. Invented hash names return NXDOMAIN, which
# would teach models that high-entropy names are NXDOMAIN-ish — rcode is a real tunnel
# signal, so the benign class must not pollute it. These zones do resolve.
EDGE_ZONE_RE = re.compile(
    r"[a-z0-9][a-z0-9._-]{2,120}\.(?:cloudfront\.net|akamaized\.net|akeyours15\.me|edgesuite\.net"
    r"|edgekey\.net|azureedge\.net|fastly\.net|fastlylb\.net|cdn77\.org|cdnbuild\.net|gcdn\.co"
    r"|cloudflare\.net|cdn\.ispapi\.net|core\.windows\.net|s3\.amazonaws\.com|storage\.googleapis\.com"
    r"|akamai\.net|akadns\.net|bitgravity\.com|edgecastcdn\.net)",
    re.IGNORECASE,
)

_LABEL_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")
MAX_NAME_LEN = 253


def is_valid_fqdn(name: str) -> bool:
    """True if *name* is a syntactically valid DNS query name (no wildcard, no IDN)."""
    if not name:
        return False
    stripped = name.rstrip(".")
    if len(stripped) > MAX_NAME_LEN or "." not in stripped:
        return False
    return all(_LABEL_RE.match(label) for label in stripped.split("."))


def _read_tranco(blob: bytes) -> str:
    """Unwrap the distributed zip; a plain CSV body is accepted too."""
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as archive:
            return archive.read(archive.namelist()[0]).decode("utf-8", errors="replace")
    except zipfile.BadZipFile:
        return blob.decode("utf-8", errors="replace")


def _parse_tranco(text: str) -> list[str]:
    domains: list[str] = []
    for row in csv.reader(text.splitlines()):
        if len(row) < 2 or row[1].strip().isdigit():
            continue  # header row is "rank,domain" with a numeric-looking second field
        domain = row[-1].strip().rstrip(".").lower()
        if is_valid_fqdn(domain):
            domains.append(domain)
    return domains


def load_fallback(path: Path | str = FALLBACK_FILE) -> list[str]:
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return [ln.strip().lower() for ln in lines if ln.strip() and not ln.startswith("#")]


def load_top_domains(
    limit: int = 1000,
    cache_dir: Path | str | None = DEFAULT_CACHE,
    timeout: float = 60.0,
    allow_network: bool = True,
) -> list[str]:
    """Return up to *limit* popular domains: cache, then Tranco, then the bundled fallback."""
    cache = None if cache_dir is None else Path(cache_dir) / "top-1m.csv"

    if cache is not None and cache.is_file():
        domains = _parse_tranco(cache.read_text(encoding="utf-8", errors="replace"))
        if len(domains) >= min(limit, 50):
            return domains[:limit]

    if allow_network:
        try:
            with urllib.request.urlopen(TRANCO_URL, timeout=timeout) as resp:
                text = _read_tranco(resp.read())
            domains = _parse_tranco(text)
            if not domains:
                raise ValueError("Tranco list parsed to zero domains")
            if cache is not None:
                cache.parent.mkdir(parents=True, exist_ok=True)
                cache.write_text(text, encoding="utf-8")
            log.info("loaded %d Tranco domains from %s", len(domains), TRANCO_URL)
            return domains[:limit]
        except Exception as exc:  # offline CI, DNS-blocked testbed, HTTP hiccup
            log.warning("Tranco fetch failed (%s); using bundled fallback", exc)

    return load_fallback()[:limit]


def extract_edge_hosts(html: str) -> set[str]:
    """Real CDN hostnames referenced by a page's markup."""
    hosts: set[str] = set()
    for match in EDGE_ZONE_RE.finditer(html):
        name = match.group(0).lower().strip(".")
        if is_valid_fqdn(name) and name.count(".") >= 2:
            hosts.add(name)
    return hosts


def harvest_edge_hosts(
    pool: list[str],
    max_pages: int = 40,
    max_hosts: int = 300,
    timeout: float = 6.0,
) -> list[str]:
    """Fetch a sample of top-site pages and collect the hashed edge names they reference."""
    headers = {"User-Agent": USER_AGENT, "Accept": "text/html,*/*"}
    hosts: set[str] = set()
    tried = 0
    for domain in pool:
        if tried >= max_pages or len(hosts) >= max_hosts:
            break
        tried += 1
        html = ""
        for url in (f"https://www.{domain}/", f"https://{domain}/"):
            try:
                with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=timeout) as resp:
                    html = resp.read(1_000_000).decode("utf-8", errors="replace")
            except Exception:
                continue
            if html:
                break
        hosts |= extract_edge_hosts(html)
    return sorted(hosts)


def random_hash_label(rng: random.Random, charset: str, lo: int, hi: int) -> str:
    return "".join(rng.choice(charset) for _ in range(rng.randint(lo, hi)))


def random_cdn_fqdn(rng: random.Random, zones: tuple[str, ...] = CDN_ZONES) -> str:
    """A believable hashed edge hostname, e.g. ``d3b8x9k2q1m7po.cloudfront.net``."""
    zone = rng.choice(zones)
    style = rng.random()
    if style < 0.45:
        label = random_hash_label(rng, _HEX, 13, 16)
    elif style < 0.75:
        label = "d" + random_hash_label(rng, _B32, 9, 12)
    elif style < 0.9:
        label = random_hash_label(rng, _B32, 16, 20)
    else:
        label = f"{rng.choice('abcmnstu')}{rng.randint(1, 9)}{random_hash_label(rng, _HEX, 6, 8)}"
    return f"{label}.{zone}"


def page_hosts(
    rng: random.Random,
    domain: str,
    pool: list[str],
    third_parties: tuple[str, ...] = THIRD_PARTY_ZONES,
    edge_hosts: Sequence[str] = (),
) -> list[str]:
    """Hostnames one page view of *domain* actually looks up (publisher + assets + ads)."""
    hosts = [domain]
    if rng.random() < 0.8:
        hosts.insert(0, f"www.{domain}")
    for _ in range(rng.randint(1, 5)):
        hosts.append(rng.choice(third_parties) if rng.random() < 0.6 else rng.choice(pool))
    for _ in range(rng.randint(0, 3)):
        # Real harvested edge names where we have them; invented ones answer NXDOMAIN.
        hosts.append(rng.choice(edge_hosts) if edge_hosts and rng.random() < 0.85 else random_cdn_fqdn(rng))
    out: list[str] = []
    for host in hosts:
        if host not in out:
            out.append(host)
    return out
