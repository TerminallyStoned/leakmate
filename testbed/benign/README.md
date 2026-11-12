# Benign traffic generator

Trello card 7 (`[Joshua] Benign traffic generator (Tranco, apt, curl, browser, CDN names)`).
Generates the *benign* half of the testbed dataset: realistic lookups from several hosts so
the models never learn "high-entropy label = tunnel".

## Run it

```bash
# local processes, one per host profile, 10 minutes, ~6k lookups, resolver inside the testbed
testbed/benign/run_benign.sh --hosts 4 --minutes 10 --resolver 10.20.0.2

# containers (real distinct source IPs; needs the card-5 network)
RESOLVER_IP=10.20.0.2 TESTBED_NETWORK=ict3214_testbed \
  testbed/benign/run_benign.sh --hosts 4 --minutes 10 --docker

# no network at all: plan the lookups only (used by CI and the "does it parse" smoke test)
testbed/benign/run_benign.sh --hosts 2 --minutes 1 --target-qps 60 --no-send
```

`run_benign.sh --help` lists every flag. Output goes to `data/raw/benign/<run id>/`:
one `<host>.ndjson` sidecar per host, one `<host>.summary.json`, and `run.json` metadata.

## Engines (weighted action mix)

| engine  | what it does                                                                                                   |
| ------- | -------------------------------------------------------------------------------------------------------------- |
| `dns`   | scripted Tranco top-sites lookups (A / AAAA / occasional MX, NS, SOA, TXT) at randomised intervals             |
| `page`  | one page view: publisher + `www` + third-party assets + hashed CDN hosts. Playwright drives a real browser when installed, otherwise the same hosts are resolved directly |
| `curl`  | real `curl`-equivalent HTTPS fetches, sometimes an extra CDN asset                                             |
| `apt`   | `apt-get update` + `--download-only` install burst, at most once per 5 minutes (needs root; falls back to mirror HTTP) |
| `cdn`   | hash-like edge hostnames under `cloudfront.net`, `akamaized.net`, `akeyours15.me`, `azureedge.net`, `fastly.net`, `blob.core.windows.net`, … 85% of them (and of the asset hosts a `page` view touches) are real names harvested from top-site HTML via `--harvest-pages` (default 40 pages), because invented ones answer NXDOMAIN |

The CDN/cloud engine is the point of the card: the proposal names high-entropy-but-benign
edge names as the fix for DNS-BERT false positives, so they must be present in volume.
Invented hash names do not resolve, and `rcode` is one of the strongest tunnel signals — a
benign class that is 20% NXDOMAIN would teach the opposite of what it is there for, hence
the harvest. `--harvest-pages 0` falls back to invented names only.

## Contract mapping

Rows carry the shared schema from the CONTRACTS card verbatim:
`ts, src_host, session_id, qname, qtype, resp_size, rcode, label, tool, dataset, throttle`
(`label=0`, `tool=benign`, `dataset=testbed`) plus one extra column, `engine`, which the
parser may drop. `resp_size` and `rcode` are filled from `dig` for lookups we issue
ourselves; for traffic caused by real tools (curl, apt, browser) the resolver capture is
the source of truth, so those two cells stay empty and the parser fills them.

## Rate and scaling

Measured on a workstation against public resolvers (VMware VM, November 2026): one
`generate.py` process tops out near **7 lookups/s** because every lookup waits on `dig`
and page loads are serial. Web fetches run on a background thread, so a slow site no
longer stalls the loop; a real headless-browser page view happens at most once per
`--browser-interval` (30 s) and the rest of the page fan-out is resolved directly.

Scale with hosts, which is also what the testbed wants:

```bash
testbed/benign/run_benign.sh --hosts 4 --minutes 10 --target-qps 30   # ~16k queries
```

Inside the testbed, `--resolver` points at the container resolver (latency ~1 ms instead
of tens of ms), so the per-process ceiling is higher. `--target-qps` is the total across
hosts; each process paces at `target-qps / hosts`.

## Acceptance check

```bash
python3 testbed/benign/check_benign.py data/raw/benign/<run id>
```

Passes when the run has >5k rows (card's "done when"), names that pass DNS syntax, ≥2
source hosts, a span matching the requested window, and CDN/cloud names present.
`run_benign.sh` runs it automatically at the end.

## Dependencies and current state

- **Nothing needed to write or dry-run this code.** Tranco is fetched at run time into
  `data/external/tranco/` (never committed); if the fetch fails the bundled
  `fallback_domains.txt` (120 domains) is used, so offline runs still work.
- **Full fidelity needs card 5** (testbed network + resolver + capture). Until that exists,
  run with `--no-send`, or against the host's normal resolver — the sidecar is still valid,
  there is just no pcap to join it with.
- Playwright is optional and deliberately not in the image by default (chromium is ~400 MB);
  `pip install playwright && playwright install chromium`, or `--build-arg WITH_BROWSER=1`
  in the image. Without it, `page` still emits the multi-host lookup burst a real page makes.
  The browser is best run once and shared over the testbed network via `--browser`/`BROWSER_CDP`,
  since chromium per scaled container is heavy.
- Stdlib only otherwise: `dig` (package `dnsutils`) and `apt-get` for the tool engines.
- `tests/` runs with `python3 -m pytest testbed/benign/tests -q`.
