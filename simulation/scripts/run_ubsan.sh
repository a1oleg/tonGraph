#!/bin/bash
# Run UBSan corpus replay: find undefined behaviour in fuzz_pool.cpp.
#
# Usage:
#   bash simulation/scripts/run_ubsan.sh
#
# Output:
#   simulation/ubsan_report.txt  — UBSan diagnostics (unique violations only)
#
# Prerequisites:
#   cmake --build build-fuzz2 --target fuzz_pool_ubsan
set -e

REPO=/home/a1oleg/tonGraph
UBSAN_BIN=$REPO/build-fuzz2/test/consensus/fuzz_pool_ubsan
CORPUS_P5=$REPO/simulation/corpus_p5
CORPUS_P4A=$REPO/simulation/corpus_p4a
REPORT=$REPO/simulation/ubsan_report.txt

if [ ! -f "$UBSAN_BIN" ]; then
  echo "ERROR: $UBSAN_BIN not found. Run: cmake --build build-fuzz2 --target fuzz_pool_ubsan"
  exit 1
fi

echo "[$(date '+%H:%M:%S')] UBSan corpus replay started"
echo "corpus_p5:  $(ls "$CORPUS_P5" | wc -l) files"
echo "corpus_p4a: $(ls "$CORPUS_P4A" | wc -l) files"

> "$REPORT"

ok=0; ub=0; crash=0
for f in "$CORPUS_P5"/* "$CORPUS_P4A"/*; do
  [ -f "$f" ] || continue
  out=$(UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1" \
    "$UBSAN_BIN" "$f" -runs=1 2>&1) || {
    code=$?
    if echo "$out" | grep -q "runtime error:"; then
      # UBSan violation
      sig=$(echo "$out" | grep "runtime error:" | head -1)
      if ! grep -qF "$sig" "$REPORT" 2>/dev/null; then
        echo "=== UB in $f ===" >> "$REPORT"
        echo "$out" | grep -A3 "runtime error:" >> "$REPORT"
        echo "" >> "$REPORT"
        ub=$((ub+1))
      fi
    else
      crash=$((crash+1))
    fi
    continue
  }
  ok=$((ok+1))
done

echo "[$(date '+%H:%M:%S')] Done: ok=$ok  ub_unique=$ub  other_crashes=$crash"
echo "Report: $REPORT"
if [ $ub -gt 0 ]; then
  echo ""
  echo "=== UBSan violations ==="
  cat "$REPORT"
fi
