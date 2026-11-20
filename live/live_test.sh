#!/usr/bin/env bash
# The trained model on traffic generated live in the testbed: benign hosts and all four tunnel tools run
# while the sniffer scores every query, then python -m live.report prints what was flagged and how fast.
#
#   live/live_test.sh                                  # M1, about 8 minutes, report in live/live_test.md
#   live/live_test.sh --weights artifacts/m1_xgb/E1.pt --benign-minutes 6 --out live/live_test.md
#
# Needs Docker, the trained model (python -m eval.run --model m1 --exp E1 saves artifacts/m1_xgb/E1.pt; see
# live/README.md) and the Tranco list in data/external/. Starts the lab if it is not up. Starts from an
# empty alerts database: an existing live/alerts.db is moved into the run's log folder (printed at the start).
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEIGHTS=artifacts/m1_xgb/E1.pt
BENIGN_MIN=6
OUT=live/live_test.md
while [[ $# -gt 0 ]]; do
  case "$1" in
    --weights) WEIGHTS="$2"; shift 2 ;;
    --benign-minutes) BENIGN_MIN="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    *) echo "unknown argument: $1 (see the header of $0)" >&2; exit 2 ;;
  esac
done
cd "$REPO"
[[ -f "$WEIGHTS" ]] || { echo "$WEIGHTS not found: train it first (live/README.md)" >&2; exit 1; }

log="$(mktemp -d)"
echo "[live_test] lab up; logs in $log"
(cd testbed && docker compose up -d --wait >/dev/null)
if [[ -f live/alerts.db ]]; then
  mv -f live/alerts.db "$log/alerts.db.before"
  echo "[live_test] the existing live/alerts.db was moved to $log/alerts.db.before"
fi

# One sniffer on the lab bridge sees every lab host, including the dns2tcp and DNSExfiltrator clients,
# which talk to their own servers and not to the resolver.
live/run_live.sh --at bridge --model m1 --weights "$WEIGHTS" >"$log/sniffer.log" 2>&1 &
TOOLS=(docker compose -f testbed/tools/docker-compose.yml --profile iodine --profile dnscat2 --profile dns2tcp
  --profile dnsexfiltrator)
stop() {
  docker stop live-sniffer-bridge >/dev/null 2>&1 || true
  "${TOOLS[@]}" down >/dev/null 2>&1 || true  # the tool clients are live beacons: never leave them running
}
trap stop EXIT
for _ in $(seq 60); do grep -q '^live: ' "$log/sniffer.log" && break; sleep 1; done
grep '^live: ' "$log/sniffer.log" || { cat "$log/sniffer.log" >&2; exit 1; }

echo "[live_test] benign hosts for $BENIGN_MIN minutes, tools one after another"
testbed/benign/run_benign.sh --hosts 2 --minutes "$BENIGN_MIN" --docker --out data/raw/benign/live_test \
  --no-check >"$log/benign.log" 2>&1 &
benign=$!
# The generator first refreshes its name lists on the host, which can take minutes. Wait for its containers,
# then let benign traffic run alone for a while so each host has a window before the first tunnel starts.
for _ in $(seq 120); do
  [[ -n "$(docker ps -q --filter name=benign)" ]] && break
  kill -0 "$benign" 2>/dev/null || { cat "$log/benign.log" >&2; echo "the benign generator did not start" >&2; exit 1; }
  sleep 5
done
[[ -n "$(docker ps -q --filter name=benign)" ]] || { echo "no benign container after 10 minutes" >&2; exit 1; }
sleep 30

run() { echo "[live_test] $*"; testbed/run_tool.sh "$@" 2>&1 | tail -1; }
run --tool dnscat2 --size 4096 --rate 5
run --tool iodine --size 65536 --rate 2048
run --tool dns2tcp --size 16384 --rate 2048
run --tool dnsexfiltrator --size 4096 --rate 5
run --tool dnscat2 --size 256 --delay 5000   # low-and-slow: one query every 5 s

wait "$benign" || echo "[live_test] the benign generator exited with an error (see $log/benign.log)"
sleep 3  # let the last replies and the last batch through
docker stop live-sniffer-bridge >/dev/null
tail -1 "$log/sniffer.log"
docker run --rm -v "$REPO:/repo" --entrypoint python leakmate-live -m live.report --out "$OUT"
echo "[live_test] report written to $OUT; alerts in live/alerts.db"
