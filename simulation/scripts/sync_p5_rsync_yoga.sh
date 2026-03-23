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
MACHINE=$(hostname)

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

  # 3. Sync с machine3
  MACHINE3_IP=192.168.10.102
  SSH_OPTS3="-p 22 -i ~/.ssh/yoga1_key -o StrictHostKeyChecking=no -o ConnectTimeout=5"

  rsync -az -e "ssh $SSH_OPTS3" \
    a1oleg@${MACHINE3_IP}:~/tonGraph/simulation/corpus_p5/ simulation/corpus_p5/ 2>/dev/null
  rsync -az -e "ssh $SSH_OPTS3" \
    simulation/corpus_p5/ a1oleg@${MACHINE3_IP}:~/tonGraph/simulation/corpus_p5/ 2>/dev/null

  # 4. Merge corpus_p4a в corpus_p5
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

  # 5. Статистика
  FUZZ_STAT=$(grep -o 'cov: [0-9]* ft: [0-9]* corp: [0-9]*.*oom/timeout/crash: [0-9]*/[0-9]*/[0-9]*' "$FUZZ_LOG" 2>/dev/null | tail -1)
  COV=$(echo "$FUZZ_STAT" | grep -o 'cov: [0-9]*' | awk '{print $2}')
  CORP=$(echo "$FUZZ_STAT" | grep -o 'corp: [0-9]*' | awk '{print $2}')
  CRASHES=$(echo "$FUZZ_STAT" | grep -o 'crash: [0-9]*' | awk '{print $2}')
  CORPUS_P5=$(ls "$REPO/simulation/corpus_p5/" 2>/dev/null | wc -l)
  CORPUS_P4A=$(ls "$REPO/simulation/corpus_p4a/" 2>/dev/null | wc -l)
  FORKS=$(pgrep -c fuzz_pool 2>/dev/null || echo "?")

  echo "[$(date '+%H:%M:%S')] sync rsync done ($MACHINE cov=${COV:-?} p5=$CORPUS_P5 forks=$FORKS)"

  sleep 120
done
