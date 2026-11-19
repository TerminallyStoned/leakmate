#!/usr/bin/env bash
# Run the live sniffer inside the testbed and write alerts to live/alerts.db.
#
#   live/run_live.sh                          # at the resolver (default)
#   live/run_live.sh --at dns2tcp-client      # inside another container's network
#   live/run_live.sh --at bridge              # on the lab bridge of the Docker host: every lab host
#   live/run_live.sh --model m1 --weights artifacts/m1_xgb/E1.pt
#
# Everything after --at is passed to `python -m live` (see its --help). Stop with Ctrl+C.
#
# Where to sniff
#   resolver   shares the resolver container's network and sniffs the interface holding 172.28.0.2.
#              Sees every client that resolves through the resolver: iodine, dnscat2, the victim and
#              the benign hosts. The resolver's own forwarded copies are dropped (--ignore-src).
#   <name>     shares that container's network (its eth0). The dns2tcp and DNSExfiltrator clients
#              talk to their own servers, not to the resolver, so sniff them at dns2tcp-client or
#              dnsexfiltrator-cli. Several sniffers can write to the same alerts.db.
#   bridge     host network, on the lab network's bridge. One sniffer for the whole lab. Needs a
#              Docker host whose bridges are visible to host-network containers (a Linux engine,
#              or Docker Desktop on WSL2, where it was checked).
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE=leakmate-live
LAB_NET=ict3214-testbed_lab
RESOLVER_IP=172.28.0.2

AT=resolver
if [[ "${1:-}" == "--at" ]]; then
  AT="${2:?--at needs resolver, bridge or a container name}"
  shift 2
fi

ctx="$(mktemp -d)"
trap 'rm -rf "$ctx"' EXIT
cp "$REPO/requirements-m1.txt" "$REPO/requirements-live.txt" "$ctx/"
docker build -q -t "$IMAGE" -f "$REPO/live/Dockerfile" "$ctx" >/dev/null

case "$AT" in
  resolver) net="container:resolver"; iface="ip:$RESOLVER_IP" ;;
  bridge)
    id="$(docker network inspect "$LAB_NET" -f '{{.Id}}')"
    net="host"; iface="br-${id:0:12}"
    ;;
  *) net="container:$AT"; iface="eth0" ;;
esac

tty=()
[[ -t 0 && -t 1 ]] && tty=(-it)
exec docker run --rm --init "${tty[@]}" --name "live-sniffer-$AT" --network "$net" \
  --cap-add NET_ADMIN --cap-add NET_RAW -v "$REPO:/repo" "$IMAGE" --iface "$iface" "$@"
