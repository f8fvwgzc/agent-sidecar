#!/usr/bin/env bash
# CPU flamegraphs of both sidecars under load, on the platform demo (scripts/local-platform.sh).
# Needs oha (brew install oha) besides the platform demo's tools. Writes, under .local/profile/<tag>:
#   orders.svg, inventory.svg      flamegraphs (open in a browser)
#   orders.folded, inventory.folded  folded stacks (scripts/flame-summary.py reads them)
#   load.txt                        oha's latency and throughput summary
#   PROFILE_TAG=after DURATION=30s CONCURRENCY=32 scripts/profile.sh
set -euo pipefail
cd "$(dirname "$0")/.."
TAG=${PROFILE_TAG:-run}
DURATION=${DURATION:-30s}
CONCURRENCY=${CONCURRENCY:-32}
OUT=$PWD/.local/profile/$TAG
rm -rf "$OUT"; mkdir -p "$OUT"
command -v oha >/dev/null || { echo "oha is required (brew install oha)"; exit 1; }

echo "▶ profiling build of the sidecar"
cargo build -q --profile profiling -p agentscd --features profiling

echo "▶ platform with profiled sidecars"
AGENTSCD=./target/profiling/agentscd PROFILE_DIR="$OUT" STOP_GRACE=120 CHECK_ONLY=0 RAISE_BUDGETS=1 \
  ./scripts/local-platform.sh >"$OUT/platform.log" 2>&1 &
PLATFORM=$!
for _ in $(seq 1 180); do
  grep -q 'platform demo ready' "$OUT/platform.log" && break
  grep -q '✗' "$OUT/platform.log" && { cat "$OUT/platform.log"; exit 1; }
  sleep 1
done
grep -q 'platform demo ready' "$OUT/platform.log" || { echo "platform did not start"; tail -30 "$OUT/platform.log"; exit 1; }

# The orders sidecar's app API: ops-assistant hands off to inventory/stock-analyst over mTLS.
echo "▶ load: $CONCURRENCY concurrent clients for $DURATION"
oha -z "$DURATION" -c "$CONCURRENCY" --no-tui -m POST -H 'content-type: application/json' \
  -d '{"input":"How many WIDGET-1 do we have in stock and should we reorder?"}' \
  http://127.0.0.1:3520/v1/agents/ops-assistant/invoke >"$OUT/load.txt"
grep -E 'Requests/sec|Average|Slowest|Fastest|99.00%|\[[0-9]{3}\]' "$OUT/load.txt" | sed 's/^/  /'

echo "▶ stopping (the sidecars write their profiles)"
kill -TERM "$PLATFORM"
wait "$PLATFORM" 2>/dev/null || true
ls -1 "$OUT"/*.svg "$OUT"/*.folded
