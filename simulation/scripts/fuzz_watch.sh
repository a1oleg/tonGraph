#!/usr/bin/env bash
# fuzz_watch.sh — monitors simulation/crashes/ for new crash files,
# minimizes each one, replays to get the violation description, commits.
#
# Usage:
#   ./simulation/scripts/fuzz_watch.sh &        # start in background
#   kill %1                                      # stop
#
# Start before or after the fuzzer — order doesn't matter.
# Committed reports go to: simulation/crash_reports/<hash>/

set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
CRASHES="$REPO/simulation/crashes"
REPORTS="$REPO/simulation/crash_reports"
STANDALONE="$REPO/build-linux/simulation/fuzz_harness_standalone"
FUZZ_BIN="$REPO/build-fuzz/simulation/fuzz_harness"

mkdir -p "$CRASHES" "$REPORTS"

log() { echo "[watch $(date '+%H:%M:%S')] $*"; }

process_crash() {
    local src="$1"
    local hash
    hash=$(sha256sum "$src" | cut -c1-12)
    local report_dir="$REPORTS/$hash"

    # Skip if already processed
    [[ -d "$report_dir" ]] && return 0
    mkdir -p "$report_dir"

    log "new crash: $(basename "$src") → $hash"

    # Copy raw input
    cp "$src" "$report_dir/input"

    # Minimize (requires fuzzer binary built with clang)
    local min_input="$report_dir/input-min"
    if [[ -x "$FUZZ_BIN" ]]; then
        "$FUZZ_BIN" -minimize_crash=1 \
            -exact_artifact_path="$min_input" \
            "$src" 2>/dev/null \
            || cp "$src" "$min_input"
    else
        cp "$src" "$min_input"
    fi

    local orig_size min_size
    orig_size=$(wc -c < "$src")
    min_size=$(wc -c < "$min_input")
    log "  minimized: ${orig_size}B → ${min_size}B"

    # Replay minimized input to get violation description
    local violations
    violations=$(cd "$REPO" && \
        "$STANDALONE" "$min_input" 2>&1 | \
        grep -E "\[fuzz\] (SAFETY|INVARIANT) VIOLATION" || true)

    [[ -z "$violations" ]] && \
        violations="[fuzz] unknown violation (replay did not reproduce)"

    # Write human-readable report
    cat > "$report_dir/report.txt" <<EOF
hash:       $hash
found:      $(date -Iseconds)
orig_size:  ${orig_size} bytes
min_size:   ${min_size} bytes

violations:
$(echo "$violations" | sed 's/^/  /')
EOF

    log "  $(echo "$violations" | head -1 | sed 's/\[fuzz\] //')"

    # Short commit title (max 72 chars)
    local title
    title=$(echo "$violations" | head -1 | \
        sed 's/\[fuzz\] //' | sed 's/ sessionId=.*//' | cut -c1-72)
    [[ -z "$title" ]] && title="unknown violation"

    # Commit the report directory
    cd "$REPO"
    git add "simulation/crash_reports/$hash/"
    git commit -m "$(cat <<COMMITMSG
crash: $title

hash: $hash
min_size: ${min_size}B (was ${orig_size}B)
found: $(date -Iseconds)
$(echo "$violations" | sed 's/^/  /')
COMMITMSG
)"
    log "  committed: simulation/crash_reports/$hash"
}

log "watching $CRASHES (PID $$)"
log "reports  → $REPORTS"

declare -A seen

while true; do
    for f in \
        "$CRASHES"/crash-* \
        "$CRASHES"/oom-* \
        "$CRASHES"/timeout-*
    do
        [[ -f "$f" ]] || continue
        name="$(basename "$f")"
        [[ "${seen[$name]+_}" ]] && continue
        seen["$name"]=1
        process_crash "$f" || log "ERROR: failed to process $f"
    done
    sleep 10
done
