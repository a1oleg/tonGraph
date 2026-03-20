#!/bin/bash
set -e
REPO=/home/a1oleg/tonGraph
BRANCH=testnet

while true; do
  cd $REPO

  # Запушить новые файлы своего corpus
  git add simulation/corpus_p4b/ 2>/dev/null
  if ! git diff --cached --quiet; then
    git commit -m "corpus p4b sync $(date '+%H:%M')"
    git push origin $BRANCH
  fi

  # Забрать corpus машины 1
  git pull --rebase origin $BRANCH 2>/dev/null || git pull origin $BRANCH

  # Merge corpus p4a в p4b
  if [ -d simulation/corpus_p4a ] && [ "$(ls -A simulation/corpus_p4a)" ]; then
    mkdir -p simulation/corpus_p4b_merged
    ./build-fuzz2/test/consensus/fuzz_pool -merge=1 \
      simulation/corpus_p4b_merged/ \
      simulation/corpus_p4b/ \
      simulation/corpus_p4a/ \
      2>/dev/null
    if [ "$(ls -A simulation/corpus_p4b_merged)" ]; then
      mv simulation/corpus_p4b_merged/* simulation/corpus_p4b/
    fi
    rmdir simulation/corpus_p4b_merged 2>/dev/null || true
  fi

  echo "[$(date '+%H:%M:%S')] sync done"
  sleep 600
done
