#!/usr/bin/env bash
# Non-sudo containment evidence for card #5. Writes docs/containment_evidence.txt.
# The tcpdump screenshot (docs/containment.png) is captured separately by hand.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/../docs/containment_evidence.txt"
mkdir -p "$HERE/../docs"

{
  echo "=== ICT3214 testbed containment evidence ==="
  date -u +"Generated: %Y-%m-%d %H:%M:%S UTC"
  echo

  echo "--- 1. Containers up ---"
  docker compose -f "$HERE/docker-compose.yml" ps
  echo

  echo "--- 2. lab network is internal:true (no gateway to the internet) ---"
  docker network inspect ict3214-testbed_lab -f 'lab internal = {{.Internal}}'
  echo

  echo "--- 3. tunnel.test resolves ONLY to the internal attacker NS (172.28.0.3) ---"
  docker exec victim dig +short abc123.secret.tunnel.test
  docker exec victim dig +short "run-${RANDOM}.exfil.tunnel.test"
  echo

  echo "--- 4. A real domain still resolves (resolver forwards non-test upstream) ---"
  docker exec victim dig +short example.com
  echo

  echo "--- 5. The victim has NO direct internet route (can only talk DNS to the resolver) ---"
  docker exec victim ping -c2 -W2 1.1.1.1 || echo "OK: victim cannot reach the internet directly"
} | tee "$OUT"

echo
echo "Wrote $OUT"
