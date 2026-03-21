#!/bin/bash
# yoga1 (4 cores, 10GB) — Phase 5 fuzzer
cd "$(dirname "$0")/.."

BINARY=./build-fuzz2/test/consensus/fuzz_pool
LOG=simulation/fuzz_p5_yoga.log
CRASHES=simulation/crashes_p5_yoga
mkdir -p "$CRASHES" simulation/corpus_p5

echo "Starting fuzz_pool at $(date)" >> "$LOG"
echo "Crashes → $CRASHES"

tmux new-session -d -s fuzz_p5 \
  "$BINARY simulation/corpus_p4a simulation/corpus_p5 \
   -fork=4 \
   -ignore_crashes=1 \
   -artifact_prefix=$PWD/$CRASHES/ \
   -use_value_profile=1 \
   $@ \
   >> $PWD/$LOG 2>&1"

echo "PID=tmux:fuzz_p5 FORKS=4 LOG=$LOG"
