#!/bin/bash
# Run MSan corpus replay: find uninitialised-memory use in fuzz_pool.cpp.
#
# Usage:
#   bash simulation/scripts/run_msan.sh
#
# Output:
#   simulation/msan_report.txt  — unique MSan violations
#
# Prerequisites:
#   cmake --build build-fuzz2 --target fuzz_pool_msan
set -e

REPO=/home/a1oleg/tonGraph
MSAN_BIN=$REPO/build-fuzz2/test/consensus/fuzz_pool_msan
CORPUS_P5=$REPO/simulation/corpus_p5
CORPUS_P4A=$REPO/simulation/corpus_p4a
REPORT=$REPO/simulation/msan_report.txt

if [ ! -f "$MSAN_BIN" ]; then
  echo "ERROR: $MSAN_BIN not found. Run: cmake --build build-fuzz2 --target fuzz_pool_msan"
  exit 1
fi

echo "[$(date '+%H:%M:%S')] MSan corpus replay started"
echo "corpus_p5:  $(ls "$CORPUS_P5" | wc -l) files"
echo "corpus_p4a: $(ls "$CORPUS_P4A" | wc -l) files"

> "$REPORT"

ok=0; msan=0; crash=0
for f in "$CORPUS_P5"/* "$CORPUS_P4A"/*; do
  [ -f "$f" ] || continue
  out=$(MSAN_OPTIONS="print_stats=1:halt_on_error=1" \
    "$MSAN_BIN" "$f" -runs=1 2>&1) || {
    code=$?
    if echo "$out" | grep -q "MemorySanitizer:"; then
      sig=$(echo "$out" | grep "MemorySanitizer:" | head -1)
      if ! grep -qF "$sig" "$REPORT" 2>/dev/null; then
        echo "=== MSan in $f ===" >> "$REPORT"
        echo "$out" | grep -A5 "MemorySanitizer:" >> "$REPORT"
        echo "" >> "$REPORT"
        msan=$((msan+1))
      fi
    else
      crash=$((crash+1))
    fi
    continue
  }
  ok=$((ok+1))
done

echo "[$(date '+%H:%M:%S')] Done: ok=$ok  msan_unique=$msan  other_crashes=$crash"
echo "Report: $REPORT"
if [ $msan -gt 0 ]; then
  echo ""
  echo "=== MSan violations ==="
  cat "$REPORT"
fi
