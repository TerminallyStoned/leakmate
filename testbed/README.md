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

## Tear down

```bash
docker compose down
```
