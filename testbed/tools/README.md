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
`parser/testbed.py` keeps that mapping in one place (`LAB_IPS` plus `--tools-map`).

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
  and the record type is NULL. `parser/pcap.py` keeps them as one character per
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

## Acceptance, as re-run on 15 Nov 2026

Re-run after the capture scripts were replaced by `parser/testbed.py`, so the rows below
are the group's contract-validated table, not the old stopgap sidecar. Both runs passed
`python contracts.py <file>` (`ok`) with `label=1`, `tool=<tool>`, `dataset=testbed`.

* dns2tcp: `run_tool.sh --tool dns2tcp --size 32768 --rate 2000 --capture` →
  `pulled 32768 bytes in 16.4s (2000 B/s)`,
  `PASS 32768 bytes through the DNS tunnel (md5 c0d80dd554d7cb58840c124b283db680)`,
  `→ …/dns2tcp_queries.parquet: 130 rows`. All 130 are TXT/NOERROR, `throttle=0`, and they
  sit in a sub-second burst: the DNS volume is the tunnel's bootstrap, the 2 KB/s cap is TCP.
* dnsexfiltrator: `--size 12288 --rate 5 --capture` → `init ok; sending 88 chunks`,
  `done: 89 queries`, `PASS reassembled 12288 bytes from /out/payload.bin.zip`,
  `→ …/dnsexfiltrator_queries.parquet: 89 rows` (89 sent = 89 parsed), span 17.1 s =
  **5.2 queries/s**, `throttle=200` (ms, from `--rate 5`).
* Two capture bugs were found by comparing the parse against what the tool reported, and
  both are fixed here rather than documented as noise: the images have no `pkill`, so the
  `docker exec -d` capture was never stopped and each run read a stale, block-buffered
  `/tmp/cap.pcap` (dnsexfiltrator under-reported 84 of 89 queries, dns2tcp over-reported
  134 of 130 because five writers had shared the file); and the receiver check ran without
  `-i`, so its heredoc never reached Python and it printed neither PASS nor FAIL. The PID is
  now recorded and signalled, and the check is `docker exec -i`.

Parsing is `python -m parser testbed` (`parser/testbed.py`, dpkt): it labels every query by
its sender address, joins the matching reply for `resp_size`/`rcode`, stamps `source_file`
and `split`, and validates the table through `contracts.validate_queries` before writing,
so a capture that does not parse fails loudly instead of landing in a dataset.

## From captures to a dataset

One command builds the table `eval/experiments.py` reads. Pass every capture window once —
for benign traffic use the capture taken at the resolver, not the run's sidecar, because the
two are views of the same lookups and their timestamps differ by `dig` latency (measured
44 ms, tail over half a second), which no merge can tell apart from duplicate traffic:

```bash
python -m parser testbed \
    --capture data/raw/testbed/<run id>/benign.pcap \
    --capture testbed/out/dns2tcp_<utc>.pcap \
    --capture testbed/out/dnsexfiltrator_<utc>.pcap \
    --capture testbed/out/dnsexfiltrator_slow_<utc>.pcap@200 \
    --out data/processed/testbed/queries.parquet
python -m parser features --dataset testbed
python -m eval.run --model m1 --exp E1
```

`@<ms>` is that capture's throttle in milliseconds (0 when absent): dnsexfiltrator is
1000/--rate, iodine/dnscat2 take it from `--delay`, and dns2tcp is 0 because its pacing
lands on the TCP transfer, not on DNS.

## Tests

```bash
python3 -m pytest tests/test_testbed.py -q    # offline: hand-built lab captures, no docker
```
