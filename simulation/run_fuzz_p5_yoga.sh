#!/bin/bash
# yoga1 (4 cores, 10GB) — Phase 5 fuzzer
cd "$(dirname "$0")/.."

REPO=/home/a1oleg/tonGraph
BINARY=$REPO/build-fuzz2/test/consensus/fuzz_pool
LOG=$REPO/simulation/fuzz_p5_yoga.log
CRASHES=$REPO/simulation/crashes_p5_yoga
mkdir -p "$CRASHES" "$REPO/simulation/corpus_p5"

echo "Starting fuzz_pool at $(date)" >> "$LOG"
echo "Crashes → $CRASHES"

# corpus_p4a excluded: sync_p5.sh merges it into corpus_p5 each cycle.
nohup $BINARY $REPO/simulation/corpus_p5 \
  -fork=4 \
  -ignore_crashes=1 \
  -artifact_prefix=$CRASHES/ \
  -use_value_profile=1 \
  "$@" \
  >> "$LOG" 2>&1 &

echo $! > /tmp/fuzz_p5.pid
echo "PID=$! FORKS=4 LOG=$LOG"
