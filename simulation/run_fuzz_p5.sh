#!/bin/bash
# Usage: ./simulation/run_fuzz_p5.sh [extra libfuzzer args]
cd "$(dirname "$0")/.."

BINARY=./build-fuzz2/test/consensus/fuzz_pool
LOG=simulation/fuzz_p5.log
CRASHES=/tmp/fuzz_crashes_p5
mkdir -p "$CRASHES"

echo "Starting fuzz_pool at $(date)" >> "$LOG"
echo "Crashes → $CRASHES"

# corpus_p4a excluded: sync_p5.sh merges it into corpus_p5 each cycle.
nohup $BINARY simulation/corpus_p5 \
  -fork=$(nproc) \
  -ignore_crashes=1 \
  -artifact_prefix="$CRASHES/" \
  -use_value_profile=1 \
  "$@" \
  >> "$LOG" 2>&1 &

echo $! > /tmp/fuzz_p5.pid
echo "PID=$! FORKS=$(nproc) LOG=$LOG"
