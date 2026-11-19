# Tunnel tools (card #8: dns2tcp, DNSExfiltrator)

Two tunnel tools, each a pair of containers on the card-5 `lab` network, driven by one
interface so captures can be scripted the same way for all four tools:

```bash
testbed/run_tool.sh --tool <dns2tcp|dnsexfiltrator|iodine|dnscat2> --size <bytes> --rate <bytes-per-second> [--delay MS] [--qtype T] [--encoding E] [--minutes M] [--capture] [--out DIR] [--manifest FILE] [--with-benign N]
```

`--size`/`--rate` are the same words Justin's card-6 tools take, but read them
precisely: they set the **application transfer** — size in bytes, rate as the tool's own
throttle. What each tool then puts on the DNS wire is a property of the tool, not of these
flags:

| tool          | DNS shape at 16 KB                                                                                          |
| ------------- | ----------------------------------------------------------------------------------------------------------- |
| dns2tcp       | bootstrap + **sub-second bursts**; 512 B/s shows up as bursts, not 512 B/s of queries. Measured: 68 queries inside 1 s. |
| dnsexfiltrator| one TXT query per chunk, paced by the client, so `--rate` really is queries/second. Measured at `--rate 5`: 84 queries / 16.6 s = **5.06 qps**. |

That difference matters for Experiment 5 (low-and-slow detection) and for time-to-detect: a
burst-vs-paced tunnel is a different signal.

## Topology

Everything here lives in `testbed/tools/docker-compose.yml`, joins the running
`ict3214-testbed_lab` network as `external`, and sits behind a compose **profile**, so
`docker compose up -d` in `testbed/` still brings up exactly Justin's three containers.

| container            | profile        | IP           | role                                                        |
| -------------------- | -------------- | ------------ | ----------------------------------------------------------- |
| `dns2tcpd`           | `dns2tcp`      | 172.28.0.42  | dns2tcp server + the TCP target it forwards to (HTTP on 127.0.0.1:8080) |
| `dns2tcp-client`     | `dns2tcp`      | 172.28.0.44  | runs `dns2tcpc`, `dns:` pointed at 172.28.0.42               |
| `dnsexfiltrator-ns`  | `dnsexfiltrator` | 172.28.0.41 | DNS server **and** collector (our Python 3 `server.py`)     |
| `dnsexfiltrator-cli` | `dnsexfiltrator` | 172.28.0.43 | exfil client, `dns:` pointed at 172.28.0.41                |

| `iodine-server`      | `iodine`       | 172.28.0.20  | `iodined`, authoritative for `i.tunnel.test`, tunnel gateway 10.0.0.1 |
| `iodine-client`      | `iodine`       | 172.28.0.30  | `iodine` client, dials in **through the resolver** (172.28.0.2) |
| `dnscat2-server`     | `dnscat2`      | 172.28.0.21  | dnscat2 Ruby server, authoritative for `d.tunnel.test`       |
| `dnscat2-client`     | `dnscat2`      | 172.28.0.31  | dnscat2 C client, C2 beacon **through the resolver**         |

Static IPs are deliberate: the parser labels traffic by source address, and
`scripts/parse_capture.py` keeps that mapping in one place (`--tools-map`).

Why clients point at the tool server instead of 172.28.0.2: card 5 forwards **all** of
`tunnel.test` to `attacker-ns`, and the capture that matters is the one where the tunnel
names appear. If the group later wants everything through the one resolver, add a
per-zone forward (`dns2tcp.tunnel.test` -> 172.28.0.42, `exfil.tunnel.test` ->
172.28.0.41) to `testbed/resolver/named.conf` and drop the `dns:` lines — that is Justin's
file, so it is not done here.

## iodine and dnscat2

These two go through the resolver, which forwards `i.tunnel.test` to 172.28.0.20 and
`d.tunnel.test` to 172.28.0.21 (`testbed/resolver/named.conf`). Because of that,
`--capture` records on the **client** container: there the query's source address is the
compromised host. At the tool server every query would appear to come from the resolver.

```bash
./run_tool.sh --tool iodine  --size 65536 --rate 1024 --minutes 1 --capture   # 1024 B/s, 1-minute capture
./run_tool.sh --tool iodine  --size 8192 --qtype TXT --encoding Base32 --capture
./run_tool.sh --tool dnscat2 --size 4096 --rate 2 --minutes 1 --capture       # 2 queries/s
./run_tool.sh --tool dnscat2 --size 1024 --delay 5000 --qtype TXT --capture   # low-and-slow, 1 query / 5 s
```

| flag | iodine | dnscat2 |
| ---- | ------ | ------- |
| `--size` | random bytes sent over TCP to the tunnel gateway; the server counts them | a random file the operator **downloads** from the victim; md5 must match on the server |
| `--rate` | bytes/second, paced with `pv` | queries/second (1-20), shorthand for `--delay 1000/N` |
| `--delay` | milliseconds between payload chunks, and (rounded up to whole seconds) the idle poll interval `iodine -I` | milliseconds, passed as `dnscat --delay <ms> --steady` |
| `--qtype` | `iodine -T`: NULL, PRIVATE, TXT, SRV, MX, CNAME, A | dnscat2 `type=`: TXT, CNAME, MX, A, AAAA (comma list allowed) |
| `--encoding` | `iodine -O` downstream encoding: Base32, Base64, Base64u, Base128, Raw (ignored by iodine for NULL) | not supported |
| `--minutes` | keep tunnel and capture open until that long after the transfer started | same |

`--delay` (or dnscat2's `--rate`) is the value written to the contract's `throttle`
column; without it the tool default applies and `throttle` is 0. The client container is
recreated when a setting changes. For low-and-slow runs use `--delay`: on dnscat2 it is
exact (one query per delay). On iodine `-I` only sets how often the idle tunnel polls, so
`--delay` also sends the payload as one chunk per delay, sized to average `--rate`
bytes/second. Measured on 15 Nov 2026 with `--size 320 --rate 8 --delay 5000`: 2 queries
every 5 s. Pacing the same data with `pv` alone gave 16 queries/s, because every byte it
lets through becomes its own query.

### Capture runs: `capture_matrix.sh`

```bash
testbed/capture_matrix.sh --dry-run    # list the runs
testbed/capture_matrix.sh --quick      # 4 short runs to check the setup (about 4 minutes)
testbed/capture_matrix.sh              # the full matrix: 30 runs
```

Each row of the matrix at the top of the script is one `run_tool.sh --capture` run: three
payload sizes, two throttles and two encodings per tool, plus three low-and-slow runs per
tool (one query or chunk every 5 s or 10 s). Edit the rows, or pass your own file with
`--matrix`. A failed run is logged and the rest carry on.

Benign traffic runs for the whole matrix (`--benign-hosts`, default 2, at `--benign-qps`
10 in total) and is captured at the resolver by a helper container, since the resolver
image has no tcpdump. That capture leaves out the two tool clients, whose queries are
already in their own pcaps.

The resolver is on two networks, lab and upstream, and Docker does not fix which one is
`eth0`. The helper therefore captures on the interface that holds the resolver's lab
address (172.28.0.2). The script waits for the first lookup from a lab host before it
starts the runs, and a benign capture with no such lookup fails the session and is not
added to the manifest.

Everything lands under `data/raw/`:

| path | what |
| ---- | ---- |
| `tools/<tool>_<size>_<rate>_<encoding>_<utc>.pcap` | one per run; `<rate>` is `r<--rate>` and/or `d<--delay>ms`, `<encoding>` is the forced record type and encoding or `default` |
| `benign/benign_<n>h_with-tools_<utc>/resolver.pcap` | the benign lookups, plus the generator's own sidecars |
| `manifest.csv` | one row per pcap: tool, client IP, size, rate, `throttle_ms`, record type, encoding, benign hosts, start and end (UTC), query count, bytes, sha256, git commit |
| `logs/matrix_<utc>.log` | the full output of every run |

`run_tool.sh --capture --manifest <file>` writes the same row for any of the four tools,
so the dns2tcp and DNSExfiltrator runs can share the manifest. The script ends by printing
the `python -m parser testbed` command for the captures it just made, with each capture's
`@<throttle ms>` and the `--tools-map 172.28.0.30=iodine,172.28.0.31=dnscat2` the parser
needs for these two tools. Checked on 15 Nov 2026: the quick matrix parsed into 2,931 rows
(iodine 646, dnscat2 125, benign 2,160) and passed `python contracts.py`.

Only `data/raw/manifest.csv` is committed; the pcaps go to the shared Drive, laid out as `tools/`
and `benign/` next to the manifest, so its `file` column still resolves. Run one session at a
time: tool clients are live beacons, so a second run lands in the first run's capture.

To capture at the resolver by hand (the resolver image has no tcpdump, so a helper container
shares its network and picks the interface holding 172.28.0.2):

```bash
docker run -d --name resolver-capture --network container:resolver --cap-add NET_ADMIN --cap-add NET_RAW \
    --entrypoint sh leakmate-iodine:latest -c 'exec tcpdump -U -qi "$(ip -o -4 addr show | sed -n "s/^[0-9]*: *\([^ ]*\) *inet 172\.28\.0\.2\/.*/\1/p")" -w /tmp/resolver.pcap "udp port 53 and host 172.28.0.2"'
docker stop resolver-capture && docker cp resolver-capture:/tmp/resolver.pcap . && docker rm resolver-capture
```

The dns2tcp and DNSExfiltrator rows live in their own file, 19 runs that take about two
hours:

```bash
testbed/capture_matrix.sh --matrix testbed/capture_matrix_dns2tcp_dnsexfiltrator.txt --benign-hosts 4 --benign-qps 15
```

For DNSExfiltrator, `--rate` is queries/second and `--delay` is the gap between queries in
milliseconds (give one or the other); either one is written to `throttle`. Its encoding
column takes `base32`, and base64 is the default. dns2tcp takes `--size` and `--rate`
only. It sends in bursts, so a low `--rate` is slow in bytes but is not one query every N
seconds, and its `throttle` stays 0.

`--capture` runs tcpdump with `-U`, so every packet is written to the pcap as it arrives.
Without it the last few queries of a short capture were still in tcpdump's buffer when it
was stopped (7 of 11 queries kept in a test on 15 Nov 2026, 11 of 11 with `-U`).

Checked on 16 Nov 2026: the 59 captures in `data/raw/manifest.csv` parse into 225,561
rows (benign 111,724, iodine 36,072, DNSExfiltrator 31,320, dns2tcp 25,867, dnscat2
20,578) and pass `python contracts.py`.

One capture is left out of the manifest and the dataset:
`benign/benign_4h_with-tools_20261115T140757Z/resolver.pcap`. An earlier version of the
script captured on `eth0`, which in that session was the resolver's upstream side. Every
query in it comes from the resolver (172.19.0.2 to 1.1.1.1 / 8.8.8.8), so the four benign
hosts cannot be told apart and lookups answered from the cache are missing. Benign is
therefore 111,724 queries against the 200,000 target.

**The dnscat2 run is a scripted C2 session**, not a bulk copy. The `dnscat2-client`
container beacons in as a command session and `run_tool.sh` plays the operator on the
server console: `ping`, `download` of the `--size` file, then `exec id` and
`exec hostname`, each of which opens its own short session from the victim. The console
is the FIFO `/tmp/console` inside `dnscat2-server`, so you can add your own commands:

```bash
docker exec dnscat2-server sh -c 'printf "window -i 2\nexec whoami\n" > /tmp/console'
docker logs -f dnscat2-server        # everything the server receives (--firehose)
```

Acceptance, as run on 14 Nov 2026 (one-minute capture of each tool, parsed with
`python -m parser pcap`):

* dnscat2 `--size 4096 --rate 2 --minutes 1 --capture` → `PASS 4096 bytes downloaded from
  the victim in 24s`, `PASS 2 remote commands ran on the victim`, 133 queries over 59.2 s
  (CNAME 46, MX 44, TXT 43), all from 172.28.0.31, all with a reply.
* iodine `--size 65536 --rate 1024 --minutes 1 --capture` → `PASS 65536 bytes through the
  iodine tunnel in 61s`, 1284 queries over 58.9 s (all NULL), all from 172.28.0.30.

Things worth knowing before trusting a capture:

* iodine switches its upstream codec to Base128, so query names carry raw 8-bit bytes
  and the record type is NULL. `scripts/parse_capture.py` keeps them as one character per
  byte (latin-1); a UTF-8-only reader drops almost every iodine query.
* dnscat2 sends an `--exec` command string as the session name in its first packet, and a
  long one makes the client abort on an assertion. Keep console `exec` commands short.
* The dnscat2 console parses a leading dash in a command as its own option, so
  `exec uname -a` does nothing. Use commands without flags.
* dnscat2 only obeys `--delay` during a transfer when `--steady` is set; otherwise it
  sends the next packet as soon as a reply arrives. `run_tool.sh` sets both.
* The dnscat2 server must keep its cache on (no `--no-cache`): the resolver re-sends
  queries, and without the cache the session breaks with SERVFAIL after the handshake.
* The capture starts after the beacon is up, so the beacon's own handshake is not in the
  pcap; the two `exec` sessions each contribute a full handshake.
* The dnscat2 client container is a live beacon. Stop the profile when you are done, or
  it keeps querying during someone else's capture:
  `docker compose -f tools/docker-compose.yml --profile iodine --profile dnscat2 down`

## Run

```bash
cd testbed && docker compose up -d                       # card-5 network first
TOOL_OUT=/tmp/toolout docker compose -f tools/docker-compose.yml --profile dns2tcp --profile dnsexfiltrator up -d --build
TOOL_OUT=/tmp/toolout ./run_tool.sh --tool dns2tcp --size 100000 --rate 2000 --capture
TOOL_OUT=/tmp/toolout ./run_tool.sh --tool dnsexfiltrator --size 12288 --rate 5 --capture
```

`--capture` runs `tcpdump -i eth0 -w` inside the tool's **server** container (its DNS
traffic crosses that interface in both directions) and `--out` receives
`<tool>_<utc>.pcap`. `run_tool.sh` then parses it and fails if the parse fails.

## Acceptance, as run on 13 Nov 2026

* dns2tcp: `run_tool.sh --tool dns2tcp --size 100000 --rate 2000 --capture` →
  `PASS 100000 bytes through the DNS tunnel (md5 f267194223bc5706e3466074c4ad68d6)`,
  `pulled 100000 bytes in 50.0s (2000 B/s)`, then `parsed 384 rows`.
* dnsexfiltrator: `--size 12288 --rate 5 --capture` → `init ok; sending 88 chunks`,
  `done: 89 queries`, 4 KB payload reassembled on the server and byte-identical to the
  source inside the zip, `parsed 84 rows`.
* 84 < 89 is honest bookkeeping, not loss: the last query's reply and a 12-byte trailing
  record fall outside the capture window because tcpdump is killed while writing. The
  parser says so (`WARN dropped a trailing …partial record`) instead of hiding it.

Parsing is `scripts/parse_capture.py` (dpkt), the quick per-capture check: the query-table
columns of `docs/contracts.md` plus `resp_size` and `rcode` joined from the matching reply.
The dataset table is built by `python -m parser testbed` (next section).

## From captures to a model

`python -m parser testbed` builds `data/processed/testbed/queries.parquet` from the tool
captures and the resolver capture (labels from the client IPs above, `PCAP@MS` for the
throttle; see `parser/testbed.py`). Then train as usual:

```bash
python -m parser testbed --capture data/raw/tools/dns2tcp_<utc>.pcap     --capture data/raw/benign/resolver_<utc>.pcap --tools-map 172.28.0.30=iodine,172.28.0.31=dnscat2
python -m eval.run --model m1 --exp E1
```

## Tests

```bash
python3 -m pytest testbed/tools/tests -q      # offline: synthetic pcaps, no docker
```
