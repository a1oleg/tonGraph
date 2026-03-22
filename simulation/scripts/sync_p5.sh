#!/bin/bash
# Usage: bash sync_p5.sh [PARITY]
#   PARITY=1 (default) — sync on odd minutes  (машина 1)
#   PARITY=0           — sync on even minutes (yoga1)
set -e
REPO=/home/a1oleg/tonGraph
BRANCH=testnet
PARITY=${1:-1}
MACHINE=$(hostname)
REPORT=$REPO/contest/setups/sync_report.md

# Определить лог фаззера по имени машины
if [ "$MACHINE" = "yoga1" ]; then
  FUZZ_LOG=$REPO/simulation/fuzz_p5_yoga.log
else
  FUZZ_LOG=$REPO/simulation/fuzz_p5.log
fi

while true; do
  cd $REPO

  # Собрать статистику фаззера
  FUZZ_STAT=$(grep -o 'cov: [0-9]* ft: [0-9]* corp: [0-9]*.*oom/timeout/crash: [0-9]*/[0-9]*/[0-9]*' "$FUZZ_LOG" 2>/dev/null | tail -1)
  COV=$(echo "$FUZZ_STAT" | grep -o 'cov: [0-9]*' | awk '{print $2}')
  CORP=$(echo "$FUZZ_STAT" | grep -o 'corp: [0-9]*' | awk '{print $2}')
  CRASHES=$(echo "$FUZZ_STAT" | grep -o 'crash: [0-9]*' | awk '{print $2}')
  CORPUS_COUNT=$(ls "$REPO/simulation/corpus_p5/" 2>/dev/null | wc -l)

  # Дописать отчёт
  echo "[$(date '+%Y-%m-%d %H:%M')] $MACHINE: cov=${COV:-?} corp=${CORP:-?} corpus_p5=$CORPUS_COUNT crashes=${CRASHES:-?}" >> "$REPORT"

  # Запушить corpus + отчёт
  git add simulation/corpus_p5/ contest/setups/sync_report.md 2>/dev/null
  if ! git diff --cached --quiet; then
    git commit -m "corpus p5 sync $(date '+%H:%M')"
  fi

  # Забрать corpus машины 1 (до push — чтобы избежать rejected)
  git pull --rebase origin $BRANCH 2>/dev/null || git pull origin $BRANCH

  # Теперь push поверх актуального remote
  git push origin $BRANCH

  # Merge corpus p4a в p5
  if [ -d simulation/corpus_p4a ] && [ "$(ls -A simulation/corpus_p4a)" ]; then
    mkdir -p simulation/corpus_p5_merged
    ./build-fuzz2/test/consensus/fuzz_pool -merge=1 \
      simulation/corpus_p5_merged/ \
      simulation/corpus_p5/ \
      simulation/corpus_p4a/ \
      2>/dev/null
    if [ "$(ls -A simulation/corpus_p5_merged)" ]; then
      mv simulation/corpus_p5_merged/* simulation/corpus_p5/
    fi
    rmdir simulation/corpus_p5_merged 2>/dev/null || true
  fi

  echo "[$(date '+%H:%M:%S')] sync p5 done ($MACHINE cov=${COV:-?})"

  # Sleep until next minute with target parity (odd or even)
  now=$(date +%s)
  m=$(( now / 60 ))
  if (( m % 2 == PARITY )); then
    next=$(( (m + 2) * 60 ))
  else
    next=$(( (m + 1) * 60 ))
  fi
  sleep $(( next - now ))
done
