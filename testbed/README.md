# Testbed (card #5)

Contained DNS testbed: a recursive **resolver**, an attacker-controlled
**authoritative server** for the unregistered domain `tunnel.test`, and a
**victim** host. Tunnel traffic for `tunnel.test` stays inside the testbed.

## Layout

| Container     | Network(s)        | IP           | Role                                             |
|---------------|-------------------|--------------|--------------------------------------------------|
| `attacker-ns` | lab (internal)    | 172.28.0.3   | Authoritative NS for `tunnel.test`. Tool servers live here later. |
| `resolver`    | lab + upstream    | 172.28.0.2   | Recursive resolver. Forwards `tunnel.test` to attacker-ns, everything else to 1.1.1.1. |
| `victim`      | lab (internal)    | 172.28.0.10  | Client. DNS pointed at the resolver. No internet of its own. |
| `benign`      | lab (internal)    | dynamic      | *Optional, card 7.* Benign traffic generator. Behind `--profile benign`, so it is never started by the commands above. |

Containment comes from two things:
1. `lab` is `internal: true` (no gateway), so victims and attacker-ns cannot reach the internet.
2. The resolver forwards `tunnel.test` **only** to the internal attacker-ns, never upstream.

## Bring it up (run in WSL / Ubuntu)

```bash
cd testbed
docker compose build        # builds the victim image (needs internet)
docker compose up -d
docker compose ps           # all three should be "running"
```

## Check resolution works

```bash
# Real domain: resolver -> 1.1.1.1 -> returns a real IP
docker exec victim dig +short google.com

# Test domain: resolver -> attacker-ns -> returns 172.28.0.3, and never leaves
docker exec victim dig +short anything.random.tunnel.test
```

## Containment test (the report deliverable)

In terminal 1 (find your interface with `ip route | grep default`, usually `eth0`):

```bash
cd testbed
bash containment-test.sh eth0
```

In terminal 2, immediately:

```bash
cd testbed
bash containment-test.sh --spam
```

Terminal 1 should show the 5 real domains leaving to 1.1.1.1 and **zero**
`tunnel.test` packets. Screenshot it to `../docs/containment.png`.

## Benign traffic (card 7, opt-in)

The generator lives in [`benign/`](benign/README.md) and is a compose **profile**, so
`docker compose up -d` still brings up exactly the three containers above. To fill the lab
with realistic lookups while capturing at the resolver:

```bash
cd testbed
./benign/run_benign.sh --hosts 4 --minutes 10 --docker --out ../data/raw/benign/$(date -u +%Y%m%dT%H%M%SZ)
```

`--hosts N` scales replicas, each with its own IP on `lab`, and each writes
`<its-ip>.ndjson` — the IP is what `tcpdump` at the resolver sees, so the parser can join
sidecar rows to packets. Rows already carry `label=0, tool=benign, dataset=testbed`.

One consequence of the containment design is worth knowing before you read the numbers:
`lab` has no route, so the container cannot download Tranco, load web pages, or run the HTTP
half of `apt`/`curl`. The generator runs with `--no-http`, which keeps every engine's DNS
fan-out (a page view still resolves its CDN and third-party hosts) and drops only the TCP
traffic — measured mix over a 1-minute 2-replica run: page 844, dns 321, cdn 190, curl 91,
apt 5. Tranco and the harvested CDN names are refreshed on the host by `run_benign.sh` and
read from the mounted `../data/external/`, so nothing needs downloading inside the lab.

## Tear down

```bash
docker compose down                                     # the three core containers
docker compose --profile benign down --remove-orphans   # plus any benign replicas
```

## Tunnel tools

`tools/` (card #8: dns2tcp, DNSExfiltrator) and `run_tool.sh` live alongside this file but
use a **separate compose project** that joins `ict3214-testbed_lab` as an external network,
so nothing here changes when they run: [`tools/README.md`](tools/README.md).
