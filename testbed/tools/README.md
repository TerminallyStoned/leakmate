# Tunnel tools (card #8: dns2tcp, DNSExfiltrator)

Two tunnel tools, each a pair of containers on the card-5 `lab` network, driven by one
interface so captures can be scripted the same way for all four tools:

```bash
testbed/run_tool.sh --tool <dns2tcp|dnsexfiltrator|iodine|dnscat2> --size <bytes> --rate <bytes-per-second> [--delay MS] [--qtype T] [--encoding E] [--minutes M] [--capture] [--out DIR]
```

`--size`/`--rate` are the same words Justin's card-6 tools take, but read them
precisely: they set the **application transfer** — size in bytes, rate as the tool's own
throttle. What each tool then puts on the DNS wire is a property of the tool, not of these
flags:

| tool          | DNS shape at 16 KB                                                                                          |
| ------------- | ----------------------------------------------------------------------------------------------------------- |
| dns2tcp       | bootstrap + **sub-second bursts**; 512 B/s shows up as bursts, not 512 B/s of queries. Measured: 68 queries inside 1 s. |
| dnsexfiltrator| one TXT query per chunk, paced by the client, so `--rate` really is queries/second. Measured at `--rate 5`: 84 queries / 16.6 s = **5.06 qps**. |

That difference matters for E5 (low-and-slow detection) and for time-to-detect: a
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
| `--delay` | milliseconds, rounded up to whole seconds for `iodine -I` | milliseconds, passed as `dnscat --delay <ms> --steady` |
| `--qtype` | `iodine -T`: NULL, PRIVATE, TXT, SRV, MX, CNAME, A | dnscat2 `type=`: TXT, CNAME, MX, A, AAAA (comma list allowed) |
| `--encoding` | `iodine -O` downstream encoding: Base32, Base64, Base64u, Base128, Raw (ignored by iodine for NULL) | not supported |
| `--minutes` | keep tunnel and capture open until that long after the transfer started | same |

`--delay` (or dnscat2's `--rate`) is the value written to the contract's `throttle`
column; without it the tool default applies and `throttle` is 0. The client container is
recreated when a setting changes. For low-and-slow runs use `--delay`: on dnscat2 it is
exact (one query per delay); on iodine pace the data with a small `--rate` as well,
because `-I` only sets how often the idle tunnel polls.

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

Parsing is `scripts/parse_capture.py` (dpkt) → the CONTRACTS query table plus `resp_size`
and `rcode` joined from the matching reply. It emits exactly the contract columns, so its
output is a drop-in for Yehan's card-9 parser; when that lands this script becomes a
specialisation of it rather than a second source of truth.

## From captures to a model

The rows are half a dataset: `eval/experiments.py` (card #10) wants one Parquet query table
per dataset. `scripts/build_queries_parquet.py` is that bridge — concatenate the benign run
and the tool captures into `data/processed/testbed/queries.parquet`:

```bash
python3 scripts/parse_capture.py testbed/out/dns2tcp_<utc>.pcap --out testbed/out/dns2tcp.ndjson --tool dns2tcp
python3 scripts/build_queries_parquet.py \
    --add data/raw/benign/<run id> \
    --add testbed/out/dns2tcp.ndjson --add testbed/out/dnsexfiltrator.ndjson \
    --out data/processed/testbed/queries.parquet
python -m eval.run --model m1 --exp E1        # once eval/ merges
```

Pass **one source per capture window**. A benign sidecar and the pcap of that same run are
two views of one traffic and their timestamps differ by `dig` latency (measured 44 ms, tail
over half a second), so no fuzzy merge can separate them from two genuinely identical
lookups; the script instead warns when two sources overlap. A test loads the output through
`eval.experiments.get_split` and is skipped until card #10 merges.

## Tests

```bash
python3 -m pytest testbed/tools/tests -q      # offline: synthetic pcaps, no docker
```
