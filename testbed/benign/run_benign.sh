#!/usr/bin/env bash
# Benign traffic generator entry point (Trello card 7).
#
#   testbed/benign/run_benign.sh --hosts 4 --minutes 10 --resolver 172.28.0.2  # in testbed
#   testbed/benign/run_benign.sh --hosts 4 --minutes 10 --docker                # as containers
#
# Runs N host profiles concurrently for M minutes and writes one NDJSON sidecar per host
# under --out, then checks the run against the card's acceptance bar (>5k benign queries
# in 10 minutes, names that parse cleanly, CDN/cloud names present). Inside the testbed
# (`lab`, card 5) every container is pointed at the resolver, so tcpdump there sees it.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

HOSTS=4
MINUTES=10
TARGET_QPS=10
RESOLVER="${RESOLVER_IP:-}"
ENGINES="dns,cdn,page,curl,apt"
SEED=""
OUT=""
MODE="local"
RUN_CHECK=1
EXTRA=()

usage() {
  cat <<'EOF'
Usage: run_benign.sh [options]

  --hosts N          host profiles to run concurrently (default 4)
  --minutes M        run length in minutes (default 10)
  --resolver IP      resolver to query (default $RESOLVER_IP; inside the testbed that is
                     172.28.0.2, which --docker already assumes)
  --target-qps Q     approximate total lookups/s across hosts (default 10 => ~6k in 10 min)
  --engines LIST     comma list of dns,cdn,page,curl,apt (default all)
  --out DIR          output directory (default data/raw/benign/<run id>)
  --seed N           reproducible lookup plan
  --docker           run as scaled containers instead of local processes
  --no-send          plan lookups without touching the network (dry run)
  --no-check         skip the acceptance check at the end
  -h, --help         this text
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --hosts) HOSTS="$2"; shift 2 ;;
    --minutes) MINUTES="$2"; shift 2 ;;
    --resolver) RESOLVER="$2"; shift 2 ;;
    --target-qps) TARGET_QPS="$2"; shift 2 ;;
    --engines) ENGINES="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --seed) SEED="$2"; shift 2 ;;
    --docker) MODE="docker"; shift ;;
    --no-send) EXTRA+=(--no-send); shift ;;
    --no-check) RUN_CHECK=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

for pair in "hosts:$HOSTS" "minutes:$MINUTES"; do
  value="${pair#*:}"
  if ! [[ "$value" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    echo "--${pair%%*} must be a number, got '$value'" >&2
    exit 2
  fi
done
if [[ "$HOSTS" -lt 1 ]]; then echo "--hosts must be >= 1" >&2; exit 2; fi

RUN_ID="benign_${HOSTS}h_${MINUTES}m_$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${OUT:-$REPO_ROOT/data/raw/benign/$RUN_ID}"

if [[ "$MODE" == "docker" ]]; then
  # One compose file for the whole testbed (card 5). The benign service sits behind the
  # `benign` profile, so `docker compose up -d` in testbed/ is unaffected by this work.
  COMPOSE=(docker compose -f "$REPO_ROOT/testbed/docker-compose.yml" --profile benign)
  RESOLVER="${RESOLVER:-172.28.0.2}"   # the testbed resolver, from card 5
  mkdir -p "$OUT" "$REPO_ROOT/data/external"
  if [[ " ${EXTRA[*]-} " != *" --no-send "* ]]; then
    # The lab has no route, so the top-sites list and the harvested edge names are
    # refreshed here and bind-mounted into the containers.
    echo "preparing data/external (Tranco + harvested edge names) on the host ..."
    python3 "$SCRIPT_DIR/generate.py" --prepare || echo "WARN prepare failed; containers fall back to the bundled domain list" >&2
  fi
  export BENIGN_MINUTES="$MINUTES" BENIGN_TARGET_QPS="$TARGET_QPS" BENIGN_ENGINES="$ENGINES"
  export RESOLVER_IP="$RESOLVER" BENIGN_SEED="$SEED" BENIGN_OUT="$OUT"
  echo "benign traffic x$HOSTS -> $OUT (resolver $RESOLVER, ${MINUTES}m)"
  # --abort-on-container-exit: generate.py exits on its own after --minutes, and this is
  # the only way `up` returns while the long-running resolver is part of the project.
  STATUS=0
  "${COMPOSE[@]}" up --build --abort-on-container-exit --exit-code-from benign \
    --scale benign="$HOSTS" benign || STATUS=$?
  echo "containers finished (exit $STATUS); the stack is stopped, restart it with:
  (cd testbed && docker compose up -d)"
  if [[ "$STATUS" -eq 0 && "$RUN_CHECK" -eq 1 ]]; then
    python3 "$SCRIPT_DIR/check_benign.py" "$OUT" --window-minutes "$MINUTES" \
      --min-hosts "$(( HOSTS < 2 ? HOSTS : 2 ))" || exit 1
  fi
  exit "$STATUS"
fi

mkdir -p "$OUT"
python3 - "$OUT" "$RUN_ID" "$HOSTS" "$MINUTES" "$TARGET_QPS" "$RESOLVER" "$ENGINES" "$SEED" <<'PY'
import json, subprocess, sys, time
from pathlib import Path
out, run_id, hosts, minutes, qps, resolver, engines, seed = sys.argv[1:9]
git = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip()
meta = {
    "run_id": run_id, "tool": "benign", "hosts": int(hosts), "minutes": float(minutes),
    "target_qps": float(qps), "resolver": resolver or "system", "engines": engines,
    "seed": int(seed) if seed else None, "git": git or None,
    "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
}
Path(out, "run.json").write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(f"run {run_id}: {json.dumps(meta['engines'])} engines, resolver {meta['resolver'] or 'system'}")
PY

echo "benign traffic -> $OUT"
PIDS=()
for ((i = 1; i <= HOSTS; i++)); do
  HOST_LABEL="$(printf 'benign-%02d' "$i")"
  ARGS=(--src-host "$HOST_LABEL" --minutes "$MINUTES" --target-qps "$TARGET_QPS"
        --hosts "$HOSTS" --engines "$ENGINES" --out "$OUT/${HOST_LABEL}.ndjson"
        --summary "$OUT/${HOST_LABEL}.summary.json")
  [[ -n "$RESOLVER" ]] && ARGS+=(--resolver "$RESOLVER")
  [[ -n "$SEED" ]] && ARGS+=(--seed "$SEED")
  python3 "$SCRIPT_DIR/generate.py" "${ARGS[@]}" ${EXTRA[@]+"${EXTRA[@]}"} &
  PIDS+=($!)
done

STATUS=0
for pid in "${PIDS[@]}"; do
  wait "$pid" || STATUS=1
done
if [[ "$STATUS" -ne 0 ]]; then
  echo "WARN at least one host worker exited non-zero (see summary JSONs in $OUT)" >&2
fi

if [[ "$RUN_CHECK" -eq 1 ]]; then
  python3 "$SCRIPT_DIR/check_benign.py" "$OUT" --window-minutes "$MINUTES" \
    --min-hosts "$(( HOSTS < 2 ? HOSTS : 2 ))" || exit 1
fi
