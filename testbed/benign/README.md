# Benign traffic generator

Trello card 7 (`[Joshua] Benign traffic generator (Tranco, apt, curl, browser, CDN names)`).
Generates the *benign* half of the testbed dataset: realistic lookups from several hosts so
the models never learn "high-entropy label = tunnel".

## Run it

```bash
# inside the card-5 lab (recommended): N containers, N real source IPs, DNS via 172.28.0.2
cd testbed && ./benign/run_benign.sh --hosts 4 --minutes 10 --docker

# local processes against any resolver (your laptop's, or the lab's if reachable)
testbed/benign/run_benign.sh --hosts 4 --minutes 10 --resolver 172.28.0.2

# no network at all: plan the lookups only (used by CI and the "does it parse" smoke test)
testbed/benign/run_benign.sh --hosts 2 --minutes 1 --target-qps 60 --no-send
```

`run_benign.sh --help` lists every flag. Output goes to `--out DIR` (the repo convention is
`data/raw/benign/<run id>/`, which the script defaults to when `--out` is omitted):
one `<host>.ndjson` sidecar per host, one `<host>.summary.json`, and `run.json` metadata.

## Running inside the lab (`--docker`)

The `benign` service is defined in [`../docker-compose.yml`](../docker-compose.yml) behind
`profiles: ["benign"]`, so Justin's `docker compose up -d` is unaffected; `--docker` runs
`docker compose --profile benign up --scale benign=N`. Two things follow from `lab` being
`internal: true` with no route to the internet:

- The service runs with `--no-http`: every engine keeps its DNS fan-out (a page view still
  resolves its publisher, third-party and CDN hosts) but the TCP half of `curl`/`apt`/browser
  does not happen, because it could not leave the network anyway. `page` still dominates the
  query count (measured 1-minute 2-replica mix: page 844, dns 321, cdn 190, curl 91, apt 5).
- Tranco and the harvested CDN hostnames cannot be downloaded there, so `run_benign.sh` runs
  `generate.py --prepare` on the host first and the container reads the mounted
  `data/external/` (`tranco.csv`, `edge_hosts.txt`). Invented hash names answer NXDOMAIN, and
  `rcode` is a tunnel signal, so reusing real harvested names matters: NXDOMAIN among dig rows
  is 8.5% in the lab versus 24.7% without the file.

`--src-host auto` (the default) resolves to the container's own IPv4, so each replica writes
`<ip>.ndjson` and the label matches the source address in the resolver's pcap — that is the
join key for the parser (card 9). Two replicas once shared one `auto.ndjson` and interleaved
their JSON; `check_benign.py` now fails on malformed lines rather than warning.

## Engines (weighted action mix)

| engine  | what it does                                                                                                   |
| ------- | -------------------------------------------------------------------------------------------------------------- |
| `dns`   | scripted Tranco top-sites lookups (A / AAAA / occasional MX, NS, SOA, TXT) at randomised intervals             |
| `page`  | one page view: publisher + `www` + third-party assets + hashed CDN hosts. Playwright drives a real browser when installed, otherwise the same hosts are resolved directly |
| `curl`  | real `curl`-equivalent HTTPS fetches, sometimes an extra CDN asset                                             |
| `apt`   | `apt-get update` + `--download-only` install burst, at most once per 5 minutes (needs root; falls back to mirror HTTP) |
| `cdn`   | hash-like edge hostnames under `cloudfront.net`, `akamaized.net`, `edgesuite.net`, `azureedge.net`, `fastly.net`, `blob.core.windows.net`, `storage.googleapis.com`, … (every zone in `CDN_ZONES` was checked for delegation with `dig NS`; non-resolving zones were dropped because they can only return NXDOMAIN) 85% of them (and of the asset hosts a `page` view touches) are real names harvested from top-site HTML via `--harvest-pages` (default 40 pages), because invented ones answer NXDOMAIN |

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

Inside the lab the ceiling is similar, not better — measured 7.1 and 9.4 lookups/s for two
replicas against the container resolver, so the limit is the generator's own pacing rather
than `dig` latency. Scale with `--hosts`, not with optimism: `--target-qps` is the total
across hosts and each process paces at `target-qps / hosts`.

## Acceptance check

```bash
python3 testbed/benign/check_benign.py data/raw/benign/<run id>
```

Passes when the run has >5k rows (card's "done when"), names that pass DNS syntax, ≥2
source hosts, a span matching the requested window, and CDN/cloud names present.
`run_benign.sh` runs it automatically at the end and propagates its exit code.

Verified runs, 12 Nov 2026:

- host, public resolver: `run_benign.sh --hosts 4 --minutes 10 --target-qps 30` →
  **PASS 14022 benign queries over 799s from 4 hosts** (17.6 lookups/s, 2985 distinct names,
  engines page 7064 / dns 3086 / cdn 2134 / curl 1144 / browser 575 / apt 19, NXDOMAIN 8.3%).
- inside the card-5 lab, the card's own bar: `./benign/run_benign.sh --hosts 4 --minutes 10
  --docker` → **PASS 38873 benign queries over 1035s from 4 hosts** (5430 distinct names, mix
  page 21440 / dns 8742 / cdn 5542 / curl 3114 / apt 35), captured at the resolver at the same
  time.

### The sidecars agree with the wire

"Parses cleanly" is only meaningful against the capture, so the join was checked directly:
`tcpdump -qi eth0 -w cap.pcap 'udp port 53'` inside the `resolver` container (Alpine: `apk add
tcpdump`) while the profile ran, then parsed with `dpkt` and compared per source address.

| 10-minute lab run | sidecar | pcap |
| ----------------- | ---------------------------------------- | ---------------------------------------- |
| total queries     | 38873                                   | 38873 (ratio 1.0000)                     |
| per host          | `.4` 8901, `.5` 9919, `.6` 10419, `.7` 9634 | identical, to the query                |
| qtypes            | A 30629, AAAA 7888, SOA 95, NS 91, MX 88, TXT 82 | identical                              |

So `src_host` is the address the capture shows and nothing was lost or double-counted — the
parser (card 9) can join on it. `resp_size` and `rcode` should be read from the pcap rather
than the sidecar where they differ: the sidecar's copy only covers lookups the generator issued
itself, while the capture sees what the resolver actually answered.

## Dependencies and current state

- **Nothing needed to write or dry-run this code.** Tranco is fetched at run time into
  `data/external/tranco.csv` (never committed; same path the M2 scripts read); if the fetch fails the bundled
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
