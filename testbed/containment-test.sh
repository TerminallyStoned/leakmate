#!/usr/bin/env bash
# Card #5 containment proof.
# Shows that tunnel.test queries never leave the host, while real domains do.
#
# Run this in WSL. It needs sudo for tcpdump. Screenshot the output -> docs/containment.png
set -euo pipefail

IFACE="${1:-eth0}"   # WSL's internet-facing interface. Check with: ip route | grep default

echo "[*] Sniffing DNS on $IFACE for 20s. Any line containing 'tunnel.test' = LEAK."
echo "[*] In another terminal, run:  bash containment-test.sh --spam"
echo

if [[ "${1:-}" == "--spam" ]]; then
    echo "[*] Firing 30 tunnel.test lookups + 5 real lookups through the resolver..."
    for i in $(seq 1 30); do
        docker exec victim dig +short "data${i}-$RANDOM.tunnel.test" >/dev/null 2>&1 || true
    done
    for d in google.com cloudflare.com github.com example.com wikipedia.org; do
        docker exec victim dig +short "$d" >/dev/null 2>&1 || true
    done
    echo "[*] Done. Check the sniffer terminal: it should show the 5 real domains"
    echo "    going to 1.1.1.1, and ZERO 'tunnel.test' packets."
    exit 0
fi

# -A prints packet payload as ASCII so you can eyeball the query names.
sudo timeout 20 tcpdump -ni "$IFACE" -A 'udp port 53' | tee /tmp/dns-egress.txt || true

echo
echo "=== Lines mentioning tunnel.test on the wire (should be EMPTY) ==="
grep -i 'tunnel.test' /tmp/dns-egress.txt && echo "!!! LEAK DETECTED" || echo "OK: no tunnel.test left the host."
