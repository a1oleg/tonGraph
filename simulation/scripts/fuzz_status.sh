#!/usr/bin/env bash
# fuzz_status.sh — quick status check: run this to see "how are things going"
#
# Usage: ./simulation/scripts/fuzz_status.sh

REPO="$(cd "$(dirname "$0")/../.." && pwd)"

sep() { echo "───────────────────────────────────────"; }

echo "=== fuzz status  $(date '+%Y-%m-%d %H:%M:%S') ==="
echo ""

# ── Fuzzer process ───────────────────────────────────────────────────────────
if pgrep -f "fuzz_harness" > /dev/null 2>&1; then
    workers=$(pgrep -c -f "fuzz_harness" || echo "?")
    echo "fuzzer:   RUNNING  ($workers workers)"
    # Show how long it has been running
    pid=$(pgrep -f "fuzz_harness" | head -1)
    if [[ -n "$pid" ]]; then
        elapsed=$(ps -o etime= -p "$pid" 2>/dev/null | tr -d ' ' || echo "?")
        echo "uptime:   $elapsed"
    fi
else
    echo "fuzzer:   stopped"
fi
echo ""

# ── Crashes ──────────────────────────────────────────────────────────────────
sep
raw_count=$(ls "$REPO/simulation/crashes"/crash-* 2>/dev/null | wc -l)
report_dirs=("$REPO/simulation/crash_reports"/*/  )
report_count=0
[[ -d "$REPO/simulation/crash_reports" ]] && \
    report_count=$(find "$REPO/simulation/crash_reports" -mindepth 1 -maxdepth 1 -type d | wc -l)

echo "crashes raw:       $raw_count  (in simulation/crashes/)"
echo "crashes committed: $report_count  (in simulation/crash_reports/)"

if [[ $report_count -gt 0 ]]; then
    echo ""
    echo "committed:"
    for d in "$REPO/simulation/crash_reports"/*/; do
        [[ -f "$d/report.txt" ]] || continue
        hash=$(basename "$d")
        found=$(grep "^found:" "$d/report.txt" | awk '{print $2}')
        viols=$(grep -A4 "^violations:" "$d/report.txt" | grep "\[fuzz\]" | \
            head -1 | sed 's/  \[fuzz\] //' | cut -c1-60)
        printf "  %-14s  %-20s  %s\n" "$hash" "$found" "$viols"
    done
fi
echo ""

# ── Corpus ───────────────────────────────────────────────────────────────────
sep
seed_count=$(ls "$REPO/simulation/corpus_fuzz/" 2>/dev/null | wc -l)
run_count=0
[[ -d "$REPO/simulation/corpus_fuzz_run" ]] && \
    run_count=$(ls "$REPO/simulation/corpus_fuzz_run/" 2>/dev/null | wc -l)

echo "corpus seed:  $seed_count inputs  (simulation/corpus_fuzz/)"
echo "corpus run:   $run_count inputs  (simulation/corpus_fuzz_run/)"
echo ""

# ── Log tail ─────────────────────────────────────────────────────────────────
sep
if [[ -f "$REPO/simulation/fuzz.log" ]]; then
    log_size=$(wc -l < "$REPO/simulation/fuzz.log")
    echo "fuzz.log ($log_size lines) — last 5:"
    tail -5 "$REPO/simulation/fuzz.log" | sed 's/^/  /'
else
    echo "fuzz.log: not found  (redirect fuzzer output: ... >> simulation/fuzz.log 2>&1)"
fi
echo ""
