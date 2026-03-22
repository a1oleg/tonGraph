#!/bin/bash
# Generate llvm-cov HTML coverage report from current corpus.
#
# Usage:
#   bash simulation/scripts/gen_coverage.sh
#
# Output:
#   simulation/coverage_report/index.html  — line+branch coverage for fuzz_pool.cpp
#   simulation/coverage_report/coverage.txt — text summary (uncovered lines)
#
# Prerequisites:
#   cmake --build build-fuzz2 --target fuzz_pool_cov
set -e

REPO=/home/a1oleg/tonGraph
COV_BIN=$REPO/build-fuzz2/test/consensus/fuzz_pool_cov
CORPUS_P5=$REPO/simulation/corpus_p5
CORPUS_P4A=$REPO/simulation/corpus_p4a
PROFRAW=$REPO/simulation/corpus.profraw
PROFDATA=$REPO/simulation/corpus.profdata
REPORT_DIR=$REPO/simulation/coverage_report
SOURCE=$REPO/test/consensus/fuzz_pool.cpp

LLVM_PROFDATA=/usr/bin/llvm-profdata-18
LLVM_COV=/usr/bin/llvm-cov-18

if [ ! -f "$COV_BIN" ]; then
  echo "ERROR: $COV_BIN not found. Run: cmake --build build-fuzz2 --target fuzz_pool_cov"
  exit 1
fi

echo "[1/4] Running corpus through fuzz_pool_cov (per-file, crash-safe)..."
PROFRAW_DIR=$REPO/simulation/profraw_tmp
rm -rf "$PROFRAW_DIR" && mkdir -p "$PROFRAW_DIR"

i=0
for f in "$CORPUS_P5"/* "$CORPUS_P4A"/*; do
  [ -f "$f" ] || continue
  LLVM_PROFILE_FILE="$PROFRAW_DIR/$i.profraw" \
    "$COV_BIN" "$f" -runs=1 2>/dev/null || true
  i=$((i+1))
done
echo "      processed $i files, profraw dir: $(du -sh "$PROFRAW_DIR" | cut -f1)"

echo "[2/4] Merging profdata..."
"$LLVM_PROFDATA" merge -sparse "$PROFRAW_DIR"/*.profraw -o "$PROFDATA"
rm -rf "$PROFRAW_DIR"
echo "      profdata: $(du -sh "$PROFDATA" | cut -f1)"

echo "[3/4] Generating HTML report..."
mkdir -p "$REPORT_DIR"
"$LLVM_COV" show "$COV_BIN" \
  -instr-profile="$PROFDATA" \
  -format=html \
  -output-dir="$REPORT_DIR" \
  -show-branches=count \
  -show-line-counts-or-regions \
  "$SOURCE"
echo "      report: $REPORT_DIR/index.html"

echo "[4/4] Text summary — uncovered regions in fuzz_pool.cpp:"
"$LLVM_COV" report "$COV_BIN" \
  -instr-profile="$PROFDATA" \
  "$SOURCE" \
  | tee "$REPORT_DIR/coverage.txt"

echo ""
echo "Uncovered lines (line# : source):"
"$LLVM_COV" show "$COV_BIN" \
  -instr-profile="$PROFDATA" \
  -format=text \
  "$SOURCE" \
  | awk '/^\s+0\|/ {printf "  line %s\n", $0}' \
  | head -60
