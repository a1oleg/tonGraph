#!/bin/bash
# Usage: ./simulation/run_fuzz_p5_yoga.sh [extra libfuzzer args]
# Yoga1 strategy: deeper mutation chains (-mutate_depth=8 -max_len=200)
cd "$(dirname "$0")/.."

BINARY=./build-fuzz2/test/consensus/fuzz_pool
LOG=simulation/fuzz_p5.log
CRASHES=/tmp/fuzz_crashes_p5
mkdir -p "$CRASHES" simulation/corpus_p5

echo "Starting fuzz_pool (yoga) at $(date)" >> "$LOG"
echo "Crashes → $CRASHES"

$BINARY simulation/corpus_p4a simulation/corpus_p5 \
  -fork=$(nproc) \
  -ignore_crashes=1 \
  -artifact_prefix="$CRASHES/" \
  -use_value_profile=1 \
  -mutate_depth=8 \
  -max_len=200 \
  "$@" \
  >> "$LOG" 2>&1 &

echo $! > /tmp/fuzz_p5.pid
echo "PID=$! FORKS=$(nproc) LOG=$LOG"
