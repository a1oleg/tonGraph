#!/bin/bash
# Sync script for Phase 5 fuzzing (both machines use this).
# Merges local corpus_p5 → corpus_p4a (tracked), pushes, pulls remote.
# Run once per machine in a separate tmux window.
set -e
REPO=~/tonGraph
BRANCH=testnet
BINARY=$REPO/build-fuzz2/test/consensus/fuzz_pool
MERGE_TMP=$REPO/simulation/corpus_p4a_merge_tmp

while true; do
  cd "$REPO"

  # Merge interesting inputs from local corpus_p5 into shared corpus_p4a
  if [ -d simulation/corpus_p5 ] && [ "$(ls -A simulation/corpus_p5 2>/dev/null)" ]; then
    mkdir -p "$MERGE_TMP"
    "$BINARY" -merge=1 \
      "$MERGE_TMP/" \
      simulation/corpus_p4a/ \
      simulation/corpus_p5/ \
      2>/dev/null || true
    if [ "$(ls -A "$MERGE_TMP" 2>/dev/null)" ]; then
      mv "$MERGE_TMP"/* simulation/corpus_p4a/
    fi
    rm -rf "$MERGE_TMP"
  fi

  # Push new corpus_p4a entries
  git add simulation/corpus_p4a/
  if ! git diff --cached --quiet; then
    git commit -m "corpus p5 sync $(date '+%H:%M')"
    git push origin "$BRANCH"
    echo "[$(date '+%H:%M:%S')] pushed corpus_p4a"
  fi

  # Pull other machine's contributions
  git pull --rebase origin "$BRANCH" 2>/dev/null || git pull origin "$BRANCH"
  echo "[$(date '+%H:%M:%S')] sync done (corpus_p4a: $(ls simulation/corpus_p4a | wc -l) files)"

  sleep 600
done
