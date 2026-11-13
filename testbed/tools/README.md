# Tunnel tools (card #8: dns2tcp, DNSExfiltrator)

Two tunnel tools, each a pair of containers on the card-5 `lab` network, driven by one
interface so captures can be scripted the same way for all four tools:

```bash
testbed/run_tool.sh --tool <dns2tcp|dnsexfiltrator> --size <bytes> --rate <bytes-per-second> [--minutes M] [--capture] [--out DIR]
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

Static IPs are deliberate: the parser labels traffic by source address, and
`scripts/parse_capture.py` keeps that mapping in one place (`--tools-map`).

Why clients point at the tool server instead of 172.28.0.2: card 5 forwards **all** of
`tunnel.test` to `attacker-ns`, and the capture that matters is the one where the tunnel
names appear. If the group later wants everything through the one resolver, add a
per-zone forward (`dns2tcp.tunnel.test` -> 172.28.0.42, `exfil.tunnel.test` ->
172.28.0.41) to `testbed/resolver/named.conf` and drop the `dns:` lines — that is Justin's
file, so it is not done here.

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

## Tests

```bash
python3 -m pytest testbed/tools/tests -q      # offline: synthetic pcaps, no docker
```
