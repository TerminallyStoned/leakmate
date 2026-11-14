#!/usr/bin/env bash
# iodine testbed node.
#   ROLE=server -> runs iodined, authoritative for $TOPDOMAIN, owns tun 10.0.0.1
#   ROLE=client -> dials in through the resolver, gets tun 10.0.0.2
set -euo pipefail

ROLE="${ROLE:?set ROLE=server or client}"
PASSWORD="${TUNNEL_PASSWORD:-s3cr3t}"
TOPDOMAIN="${TOPDOMAIN:-i.tunnel.test}"
TUN_SERVER_IP="${TUN_SERVER_IP:-10.0.0.1}"

if [ "$ROLE" = "server" ]; then
    echo "[iodine-server] iodined for $TOPDOMAIN, tunnel gateway $TUN_SERVER_IP"
    # -f foreground, -c skip the client source-IP check (queries arrive via the
    # resolver so every client looks like the same source IP).
    exec iodined -f -c -P "$PASSWORD" "$TUN_SERVER_IP" "$TOPDOMAIN"
fi

if [ "$ROLE" = "client" ]; then
    RESOLVER="${RESOLVER:-172.28.0.2}"
    INTERVAL="${IODINE_INTERVAL:-4}"   # iodine's throttle: max seconds between requests
    sleep "${START_DELAY:-6}"        # give the server time to bind
    # -f foreground, -r force DNS mode (raw UDP can't reach the server here).
    ARGS=(-f -r -I "$INTERVAL")
    # Optional: force the DNS record type (-T) and the downstream encoding (-O, which
    # iodine only honours for record types other than NULL). Default is autodetect.
    if [ -n "${IODINE_TYPE:-}" ]; then ARGS+=(-T "$IODINE_TYPE"); fi
    if [ -n "${IODINE_ENCODING:-}" ]; then ARGS+=(-O "$IODINE_ENCODING"); fi
    echo "[iodine-client] dialing $TOPDOMAIN via resolver $RESOLVER (${ARGS[*]})"
    exec iodine "${ARGS[@]}" -P "$PASSWORD" "$RESOLVER" "$TOPDOMAIN"
fi

echo "unknown ROLE: $ROLE (use server or client)" >&2
exit 1
