#!/usr/bin/env bash
# Capture-run matrix for iodine and dnscat2: every row below is one run_tool.sh capture,
# with benign traffic running in the lab at the same time.
#
#   testbed/capture_matrix.sh --dry-run             # print the runs, start nothing
#   testbed/capture_matrix.sh --quick               # 4 short runs, to check the setup
#   testbed/capture_matrix.sh                       # the full matrix
#   testbed/capture_matrix.sh --tools dnscat2       # one tool only
#   testbed/capture_matrix.sh --matrix my_runs.txt  # your own rows (same columns)
#   testbed/capture_matrix.sh --matrix testbed/capture_matrix_dns2tcp_dnsexfiltrator.txt
#
# Output, all under data/raw/ (not committed, apart from the manifest):
#   tools/<tool>_<size>_<rate>_<encoding>_<utc>.pcap   one per run, taken on the tool client
#   benign/<run id>/resolver.pcap                      benign lookups seen at the resolver
#   manifest.csv                                       one row per pcap
#   logs/matrix_<utc>.log                              full output of every run
#
# --benign-hosts N  benign generator containers to run alongside (default 2, 0 = none)
# --benign-qps Q    their total lookups per second (default 10)
#
# A failed run is logged and the matrix carries on; the summary at the end lists them.
# The last lines print the `python -m parser testbed` command for this session's captures.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
RAW="$REPO_ROOT/data/raw"
TOOLS="" # empty = every row of the matrix
BENIGN_HOSTS=2
BENIGN_QPS=10
DRY=0
QUICK=0
MATRIX_FILE=""
IODINE_IP=172.28.0.30
DNSCAT_IP=172.28.0.31
RESOLVER_IP=172.28.0.2 # the resolver's address on the lab network

# Columns: tool size rate delay qtype encoding minutes   ("-" = leave at the tool default)
#   iodine  rate = bytes/s; delay = ms between chunks and between idle polls (low-and-slow)
#   dnscat2 rate = queries/s OR delay = ms between queries (not both)
#   dnsexfiltrator  same as dnscat2; encoding = base32 or - (base64)
#   dns2tcp rate = bytes/s only
#   minutes = keep the tunnel and capture open at least this long after the transfer starts
full_matrix() {
  cat <<'EOF'
# iodine, 3 sizes x unthrottled / 2048 B/s x default (NULL, Base128) / TXT + Base32
iodine 16384 - - - - -
iodine 65536 - - - - -
iodine 262144 - - - - -
iodine 16384 2048 - - - -
iodine 65536 2048 - - - -
iodine 262144 2048 - - - -
iodine 16384 - - TXT Base32 -
iodine 65536 - - TXT Base32 -
iodine 262144 - - TXT Base32 -
iodine 16384 2048 - TXT Base32 -
iodine 65536 2048 - TXT Base32 -
iodine 262144 2048 - TXT Base32 -
# iodine low-and-slow: one small chunk every 5 s / 10 s (size / rate = run length in s)
iodine 4096 8 5000 - - -
iodine 4096 8 5000 TXT Base32 -
iodine 4096 8 10000 - - -
# dnscat2, 3 sizes x 10 / 2 queries per second x mixed record types / TXT only
dnscat2 2048 10 - - - -
dnscat2 8192 10 - - - -
dnscat2 32768 10 - - - -
dnscat2 2048 2 - - - -
dnscat2 8192 2 - - - -
dnscat2 32768 2 - - - -
dnscat2 2048 10 - TXT - -
dnscat2 8192 10 - TXT - -
dnscat2 32768 10 - TXT - -
dnscat2 2048 2 - TXT - -
dnscat2 8192 2 - TXT - -
dnscat2 32768 2 - TXT - -
# dnscat2 low-and-slow: one query every 5 s / 10 s
dnscat2 512 - 5000 - - -
dnscat2 1024 - 5000 TXT - -
dnscat2 512 - 10000 - - -
EOF
}

quick_matrix() {
  cat <<'EOF'
iodine 8192 2048 - - - -
iodine 320 8 5000 TXT Base32 -
dnscat2 1024 10 - - - -
dnscat2 256 - 2000 TXT - -
EOF
}

usage() {
  sed -n '2,22p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tools) TOOLS="$2"; shift 2 ;;
    --benign-hosts) BENIGN_HOSTS="$2"; shift 2 ;;
    --benign-qps) BENIGN_QPS="$2"; shift 2 ;;
    --matrix) MATRIX_FILE="$2"; shift 2 ;;
    --quick) QUICK=1; shift ;;
    --dry-run) DRY=1; shift ;;
    --help | -h) usage 0 ;;
    *) echo "unknown argument: $1" >&2; usage 2 ;;
  esac
done
[[ "$BENIGN_HOSTS" =~ ^[0-9]+$ ]] || { echo "--benign-hosts must be an integer" >&2; exit 2; }

if [[ -n "$MATRIX_FILE" ]]; then
  [[ -r "$MATRIX_FILE" ]] || { echo "cannot read $MATRIX_FILE" >&2; exit 2; }
  ROWS="$(cat "$MATRIX_FILE")"
elif [[ "$QUICK" -eq 1 ]]; then
  ROWS="$(quick_matrix)"
else
  ROWS="$(full_matrix)"
fi

# Keep the rows for the chosen tools, drop comments and blank lines.
RUNS=()
while read -r tool size rate delay qtype enc minutes _; do
  [[ -z "${tool:-}" || "$tool" == \#* ]] && continue
  [[ -z "$TOOLS" || ",$TOOLS," == *",$tool,"* ]] || continue
  [[ -n "${minutes:-}" ]] || { echo "matrix row needs 7 columns: $tool $size ..." >&2; exit 2; }
  RUNS+=("$tool $size $rate $delay $qtype $enc $minutes")
done <<<"$ROWS"
((${#RUNS[@]} > 0)) || { echo "no runs selected (--tools ${TOOLS:-all})" >&2; exit 2; }

# One matrix row -> the run_tool.sh arguments.
tool_args() {
  local tool size rate delay qtype enc minutes
  read -r tool size rate delay qtype enc minutes <<<"$1"
  local a=(--tool "$tool" --size "$size")
  [[ "$rate" == "-" ]] || a+=(--rate "$rate")
  [[ "$delay" == "-" ]] || a+=(--delay "$delay")
  [[ "$qtype" == "-" ]] || a+=(--qtype "$qtype")
  if [[ "$tool" == "dnsexfiltrator" ]]; then
    # Its only encoding switch is --base32; base64 is the default.
    [[ "$enc" == "base32" ]] && a+=(--base32)
  elif [[ "$enc" != "-" ]]; then
    a+=(--encoding "$enc")
  fi
  [[ "$minutes" == "-" ]] || a+=(--minutes "$minutes")
  echo "${a[*]}"
}

if [[ "$DRY" -eq 1 ]]; then
  echo "${#RUNS[@]} runs, benign hosts alongside: $BENIGN_HOSTS"
  for i in "${!RUNS[@]}"; do
    echo "  $((i + 1)). run_tool.sh $(tool_args "${RUNS[$i]}") --capture"
  done
  exit 0
fi

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
MANIFEST="$RAW/manifest.csv"
LOG="$RAW/logs/matrix_$STAMP.log"
BENIGN_ID="benign_${BENIGN_HOSTS}h_with-tools_$STAMP"
BENIGN_DIR="$RAW/benign/$BENIGN_ID"
CORE=(docker compose -f "$SCRIPT_DIR/docker-compose.yml")
mkdir -p "$RAW/tools" "$RAW/logs"

say() { echo "[$(date -u +%H:%M:%SZ)] $*" | tee -a "$LOG"; }

BENIGN_UP=0
BENIGN_FAILED=0
BENIGN_START=""
start_benign() {
  ((BENIGN_HOSTS > 0)) || return 0
  mkdir -p "$BENIGN_DIR" "$REPO_ROOT/data/external"
  # The lab has no route out, so the top-sites list is refreshed on the host first; the
  # containers fall back to the bundled domain list if this fails.
  python3 "$SCRIPT_DIR/benign/generate.py" --prepare >>"$LOG" 2>&1 \
    || say "WARN benign --prepare failed; the generator uses its bundled domain list"
  # The generator stops by itself after BENIGN_MINUTES; a day is longer than any matrix,
  # and stop_benign ends it when the last run is done.
  export BENIGN_MINUTES=1440 BENIGN_TARGET_QPS="$BENIGN_QPS" BENIGN_OUT="$BENIGN_DIR" RESOLVER_IP
  "${CORE[@]}" --profile benign up -d --build --scale benign="$BENIGN_HOSTS" benign >>"$LOG" 2>&1 \
    || { say "FAIL could not start the benign generator (see $LOG)"; exit 1; }
  # The resolver image has no tcpdump, so the capture runs in a helper container that
  # shares the resolver's network. The tool clients are left out of it: their queries are
  # already in their own per-run pcaps and must not be counted twice.
  # The resolver sits on two networks (lab and upstream) and Docker does not fix which of
  # them is eth0, so the capture runs on the interface that holds the resolver's lab
  # address. On the upstream side every query comes from the resolver itself, the lab
  # hosts are not visible, and lookups answered from the cache are missing.
  docker rm -f resolver-capture >/dev/null 2>&1
  docker run -d --name resolver-capture --network container:resolver \
    --cap-add NET_ADMIN --cap-add NET_RAW --entrypoint sh leakmate-iodine:latest -c '
      ifc="$(ip -o -4 addr show | sed -n "s/^[0-9]*: *\([^ ]*\) *inet $1\/.*/\1/p" | head -n 1)"
      [ -n "$ifc" ] || { echo "no interface holds $2" >&2; exit 1; }
      echo "capturing on $ifc ($2)" >&2
      exec tcpdump -U -qi "$ifc" -w /tmp/resolver.pcap "$3"' \
    sh "${RESOLVER_IP//./\\.}" "$RESOLVER_IP" \
    "udp port 53 and host $RESOLVER_IP and not host $IODINE_IP and not host $DNSCAT_IP" >>"$LOG" 2>&1 \
    || { say "FAIL could not start the resolver capture (see $LOG)"; exit 1; }
  BENIGN_UP=1
  BENIGN_START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  # Do not start hours of runs on a capture that sees no lab host: wait for the first
  # benign lookup to show up in it.
  local seen=0 try
  for try in $(seq 1 12); do
    sleep 5
    seen="$(lab_queries /tmp/resolver.pcap docker exec resolver-capture tcpdump)"
    ((${seen:-0} > 0)) && break
  done
  if ((${seen:-0} == 0)); then
    docker logs resolver-capture >>"$LOG" 2>&1
    say "FAIL the resolver capture saw no lookup from a lab host in 60 s (see $LOG)"
    exit 1
  fi
  say "benign: $BENIGN_HOSTS hosts at ~$BENIGN_QPS lookups/s, $(docker logs resolver-capture 2>&1 | grep -m1 'capturing on' || echo 'capturing at the resolver')"
}

# lab_queries <pcap path as the command sees it> <command that runs tcpdump...>
# Counts lookups sent to the resolver's lab address by anyone but the resolver.
lab_queries() {
  local pcap="$1"
  shift
  "$@" -nr "$pcap" "udp dst port 53 and dst host $RESOLVER_IP and not src host $RESOLVER_IP" 2>/dev/null \
    | wc -l | tr -d '[:space:]'
}

stop_benign() {
  ((BENIGN_UP == 1)) || return 0
  BENIGN_UP=0
  local pcap="$BENIGN_DIR/resolver.pcap" end queries
  "${CORE[@]}" --profile benign stop benign >>"$LOG" 2>&1
  sleep 2
  docker stop -t 5 resolver-capture >/dev/null 2>&1 # SIGTERM: tcpdump flushes and exits
  end="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  docker cp resolver-capture:/tmp/resolver.pcap "$pcap" >>"$LOG" 2>&1
  docker rm -f resolver-capture >/dev/null 2>&1
  "${CORE[@]}" --profile benign rm -f benign >>"$LOG" 2>&1
  # Queries from lab hosts only: the resolver's own forwarded lookups are not counted.
  [[ -s "$pcap" ]] && queries="$(lab_queries /cap/resolver.pcap docker run --rm -v "$BENIGN_DIR:/cap:ro" --entrypoint tcpdump leakmate-iodine:latest)"
  if [[ -s "$pcap" ]] && ((${queries:-0} == 0)); then
    BENIGN_FAILED=1
    say "FAIL $pcap holds no lookup from a lab host; it is not added to the manifest"
  elif [[ -s "$pcap" ]]; then
    [[ -s "$MANIFEST" ]] || echo "file,tool,client_ip,size_bytes,rate,rate_unit,throttle_ms,qtype,encoding,minutes,benign_hosts,start_utc,end_utc,queries,pcap_bytes,sha256,git" >"$MANIFEST"
    echo "benign/$BENIGN_ID/resolver.pcap,benign,,0,$BENIGN_QPS,queries/s,0,default,default,,$BENIGN_HOSTS,$BENIGN_START,$end,$queries,$(wc -c <"$pcap"),$(sha256sum "$pcap" | cut -d' ' -f1),$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || true)" >>"$MANIFEST"
    say "benign capture -> $pcap ($queries client queries)"
  else
    BENIGN_FAILED=1
    say "FAIL no benign capture was written"
  fi
}
trap 'stop_benign' EXIT
trap 'say "interrupted"; exit 130' INT TERM

"${CORE[@]}" up -d --wait >>"$LOG" 2>&1 || { say "FAIL the core lab did not start (see $LOG)"; exit 1; }
# Build the tool images before the benign capture needs one of them for tcpdump.
docker compose -f "$SCRIPT_DIR/tools/docker-compose.yml" --profile iodine --profile dnscat2 build >>"$LOG" 2>&1 \
  || { say "FAIL could not build the tool images (see $LOG)"; exit 1; }
say "${#RUNS[@]} runs, log $LOG"
SESSION_START="$(date +%s)" # before the benign capture starts, so its manifest row counts as this session's
start_benign

export RUN_TIMEOUT="${RUN_TIMEOUT:-3600}" # the largest dnscat2 download at 2 queries/s takes about 20 min
OK=0
FAILED=()
for i in "${!RUNS[@]}"; do
  read -r -a ARGS <<<"$(tool_args "${RUNS[$i]}")"
  say "run $((i + 1))/${#RUNS[@]}: ${ARGS[*]}"
  T0="$(date +%s)"
  if "$SCRIPT_DIR/run_tool.sh" "${ARGS[@]}" --capture --out "$RAW/tools" \
    --manifest "$MANIFEST" --with-benign "$BENIGN_HOSTS" >>"$LOG" 2>&1; then
    OK=$((OK + 1))
    say "  ok in $(($(date +%s) - T0))s: $(tail -n +2 "$MANIFEST" | tail -1 | awk -F, '{print $1 ", " $14 " queries"}')"
  else
    FAILED+=("${ARGS[*]}")
    say "  FAILED after $(($(date +%s) - T0))s (details in the log)"
  fi
done
stop_benign

say "done: $OK of ${#RUNS[@]} runs captured in $((($(date +%s) - SESSION_START) / 60)) min"
for f in ${FAILED[@]+"${FAILED[@]}"}; do say "  failed: $f"; done

# Rows this session added, by start time, turned into the parser command.
python3 - "$MANIFEST" "$(date -u -d "@$SESSION_START" +%Y-%m-%dT%H:%M:%SZ)" "$IODINE_IP" "$DNSCAT_IP" <<'PY' | tee -a "$LOG"
import csv
import sys

manifest, since, iodine_ip, dnscat_ip = sys.argv[1:5]
rows = [r for r in csv.DictReader(open(manifest, encoding="utf-8")) if r["start_utc"] >= since]
tunnel = sum(int(r["queries"] or 0) for r in rows if r["tool"] != "benign")
benign = sum(int(r["queries"] or 0) for r in rows if r["tool"] == "benign")
print(f"this session: {tunnel} tunnel queries, {benign} benign queries in {len(rows)} captures")
print("parse them with:")
print("python -m parser testbed \\")
for r in rows:
    ms = int(r["throttle_ms"] or 0)
    print(f"  --capture data/raw/{r['file']}{'@' + str(ms) if ms else ''} \\")
print(f"  --tools-map {iodine_ip}=iodine,{dnscat_ip}=dnscat2")
PY
[[ ${#FAILED[@]} -eq 0 && $BENIGN_FAILED -eq 0 ]]
