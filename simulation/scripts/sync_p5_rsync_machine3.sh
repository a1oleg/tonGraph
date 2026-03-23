#!/bin/bash
# Corpus sync via rsync for machine3
# Usage: bash sync_p5_rsync_machine3.sh
# Runs on machine3, syncs with gigabyte1 every 2 min

REPO=/home/a1oleg/tonGraph
GIGABYTE1_IP=192.168.10.101
GIGABYTE1_SSH_PORT=2222
GIGABYTE1_KEY=~/.ssh/gigabyte1_key
GIGABYTE1_PATH=/home/a1oleg/tonGraph
FUZZ_LOG=$REPO/simulation/fuzz_p5_machine3.log
MACHINE=$(hostname)

SSH_OPTS="-p $GIGABYTE1_SSH_PORT -i $GIGABYTE1_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=5"

while true; do
  cd $REPO

  # 1. Pull corpus от gigabyte1 → machine3
  rsync -az \
    -e "ssh $SSH_OPTS" \
    a1oleg@${GIGABYTE1_IP}:${GIGABYTE1_PATH}/simulation/corpus_p5/ \
    simulation/corpus_p5/ \
    2>/dev/null

  # 2. Push corpus machine3 → gigabyte1
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

  # 4. Merge crash-seeds → corpus
  CRASH_DIR=$REPO/simulation/crashes_p5_machine3
  CRASH_STAMP=$REPO/simulation/.crashes_merged_stamp_machine3
  if [ -d "$CRASH_DIR" ] && [ "$(ls -A $CRASH_DIR 2>/dev/null)" ]; then
    mkdir -p simulation/corpus_p5_crash_merge
    if [ -f "$CRASH_STAMP" ]; then
      find "$CRASH_DIR" -newer "$CRASH_STAMP" -type f | head -200 | \
        xargs -I{} cp {} simulation/corpus_p5_crash_merge/ 2>/dev/null
    else
      find "$CRASH_DIR" -type f | head -200 | \
        xargs -I{} cp {} simulation/corpus_p5_crash_merge/ 2>/dev/null
    fi
    if [ "$(ls -A simulation/corpus_p5_crash_merge 2>/dev/null)" ]; then
      mkdir -p simulation/corpus_p5_merged
      ./build-fuzz2/test/consensus/fuzz_pool -merge=1 \
        simulation/corpus_p5_merged/ \
        simulation/corpus_p5/ \
        simulation/corpus_p5_crash_merge/ \
        2>/dev/null || true
      if [ "$(ls -A simulation/corpus_p5_merged 2>/dev/null)" ]; then
        mv simulation/corpus_p5_merged/* simulation/corpus_p5/
      fi
      rmdir simulation/corpus_p5_merged 2>/dev/null || true
      touch "$CRASH_STAMP"
    fi
    rm -rf simulation/corpus_p5_crash_merge
  fi

  # 5. Статистика
  FUZZ_STAT=$(grep -o 'cov: [0-9]* ft: [0-9]* corp: [0-9]*.*oom/timeout/crash: [0-9]*/[0-9]*/[0-9]*' "$FUZZ_LOG" 2>/dev/null | tail -1)
  COV=$(echo "$FUZZ_STAT" | grep -o 'cov: [0-9]*' | awk '{print $2}')
  CORPUS_P5=$(ls "$REPO/simulation/corpus_p5/" 2>/dev/null | wc -l)
  FORKS=$(pgrep -c fuzz_pool 2>/dev/null || echo "?")

  echo "[$(date '+%H:%M:%S')] sync rsync done ($MACHINE cov=${COV:-?} p5=$CORPUS_P5 forks=$FORKS)"

  sleep 120
done
