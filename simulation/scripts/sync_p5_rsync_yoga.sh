#!/bin/bash
# Corpus sync via rsync for yoga1
# Usage: bash sync_p5_rsync_yoga.sh
# Runs on yoga1, syncs with gigabyte1 every 2 min

REPO=/home/a1oleg/tonGraph
GIGABYTE1_IP=192.168.10.101
GIGABYTE1_SSH_PORT=2222
GIGABYTE1_KEY=~/.ssh/gigabyte1_key
GIGABYTE1_PATH=/home/a1oleg/tonGraph
FUZZ_LOG=$REPO/simulation/fuzz_p5_yoga.log
REPORT=$REPO/contest/setups/sync_report.md
MACHINE=$(hostname)
BRANCH=testnet

SSH_OPTS="-p $GIGABYTE1_SSH_PORT -i $GIGABYTE1_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=5"

while true; do
  cd $REPO

  # 1. Pull corpus от gigabyte1 → yoga1
  rsync -az \
    -e "ssh $SSH_OPTS" \
    a1oleg@${GIGABYTE1_IP}:${GIGABYTE1_PATH}/simulation/corpus_p5/ \
    simulation/corpus_p5/ \
    2>/dev/null

  # 2. Push corpus yoga1 → gigabyte1
  rsync -az \
    -e "ssh $SSH_OPTS" \
    simulation/corpus_p5/ \
    a1oleg@${GIGABYTE1_IP}:${GIGABYTE1_PATH}/simulation/corpus_p5/ \
    2>/dev/null

  # 3. Merge corpus_p4a в corpus_p5
  if [ -d simulation/corpus_p4a ] && [ "$(ls -A simulation/corpus_p4a)" ]; then
    mkdir -p simulation/corpus_p5_merged
    ./build-fuzz2/test/consensus/fuzz_pool -merge=1 \
      simulation/corpus_p5_merged/ \
      simulation/corpus_p5/ \
      simulation/corpus_p4a/ \
      2>/dev/null || true
    if [ "$(ls -A simulation/corpus_p5_merged 2>/dev/null)" ]; then
      mv simulation/corpus_p5_merged/* simulation/corpus_p5/
    fi
    rmdir simulation/corpus_p5_merged 2>/dev/null || true
  fi

  # 4. Статистика
  FUZZ_STAT=$(grep -o 'cov: [0-9]* ft: [0-9]* corp: [0-9]*.*oom/timeout/crash: [0-9]*/[0-9]*/[0-9]*' "$FUZZ_LOG" 2>/dev/null | tail -1)
  COV=$(echo "$FUZZ_STAT" | grep -o 'cov: [0-9]*' | awk '{print $2}')
  CORP=$(echo "$FUZZ_STAT" | grep -o 'corp: [0-9]*' | awk '{print $2}')
  CRASHES=$(echo "$FUZZ_STAT" | grep -o 'crash: [0-9]*' | awk '{print $2}')
  CORPUS_P5=$(ls "$REPO/simulation/corpus_p5/" 2>/dev/null | wc -l)
  CORPUS_P4A=$(ls "$REPO/simulation/corpus_p4a/" 2>/dev/null | wc -l)
  BUILD_COMMIT=$(git log -1 --format="%h" -- test/consensus/fuzz_pool.cpp 2>/dev/null)
  BUILD_DATE=$(stat -c "%y" "$REPO/build-fuzz2/test/consensus/fuzz_pool" 2>/dev/null | cut -c1-16)
  MAX_VTYPE=$(grep 'vote_type = fdp.ConsumeIntegralInRange' "$REPO/test/consensus/fuzz_pool.cpp" 2>/dev/null | grep -o '[0-9]*);' | tr -d ');' || true)
  FORKS=$(pgrep -c fuzz_pool 2>/dev/null || echo "?")

  echo "[$(date '+%Y-%m-%d %H:%M')] $MACHINE: cov=${COV:-?} corp=${CORP:-?} p5=$CORPUS_P5 p4a=$CORPUS_P4A crashes=${CRASHES:-?} | build=$BUILD_COMMIT $BUILD_DATE vtype_max=${MAX_VTYPE:-?} forks=$FORKS" >> "$REPORT"
  echo "[$(date '+%H:%M:%S')] sync rsync done ($MACHINE cov=${COV:-?} p5=$CORPUS_P5)"

  # 5. Push report в git
  git add contest/setups/sync_report.md 2>/dev/null
  if ! git diff --cached --quiet; then
    git commit -m "sync report $(date '+%H:%M')" 2>/dev/null
    git stash push -q 2>/dev/null || true
    git pull --rebase origin $BRANCH 2>/dev/null || true
    git stash pop -q 2>/dev/null || true
    for _r in 1 2 3; do
      git push origin $BRANCH 2>/dev/null && break
      git pull --rebase origin $BRANCH 2>/dev/null || true
    done
  fi

  sleep 120
done
