#!/bin/bash
set -e
REPO=~/tonGraph
BRANCH=testnet

while true; do
  cd $REPO

  # Push new corpus files
  git add simulation/corpus_p4a/ 2>/dev/null
  if ! git diff --cached --quiet; then
    git commit -m "corpus p4a sync $(date '+%H:%M')"
    git push origin $BRANCH
  fi

  # Pull corpus from machine 2
  git pull --rebase origin $BRANCH 2>/dev/null || git pull origin $BRANCH

  # Merge p4b into p4a
  if [ -d simulation/corpus_p4b ] && [ "$(ls -A simulation/corpus_p4b 2>/dev/null)" ]; then
    mkdir -p simulation/corpus_p4a_merged
    ./build-fuzz2/test/consensus/fuzz_pool -merge=1 \
      simulation/corpus_p4a_merged/ \
      simulation/corpus_p4a/ \
      simulation/corpus_p4b/ \
      2>/dev/null
    if [ "$(ls -A simulation/corpus_p4a_merged 2>/dev/null)" ]; then
      mv simulation/corpus_p4a_merged/* simulation/corpus_p4a/
    fi
    rmdir simulation/corpus_p4a_merged 2>/dev/null || true
  fi

  echo "[$(date '+%H:%M:%S')] sync done (p4a: $(ls simulation/corpus_p4a/ | wc -l) files)"
  sleep 600
done
