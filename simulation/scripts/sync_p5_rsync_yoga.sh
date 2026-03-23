#!/bin/bash
# Corpus spoke — runs on yoga1 (worker)
# Just pushes new local corpus to gigabyte1 every 2 min.
# Enrichment (merge, minimize, crash-seeds) is done by gigabyte1 orchestrator.

REPO=/home/a1oleg/tonGraph
GIGABYTE1_IP=192.168.10.101
GIGABYTE1_PORT=2222
GIGABYTE1_KEY=~/.ssh/gigabyte1_key
FUZZ_LOG=$REPO/simulation/fuzz_p5_yoga.log
MACHINE=$(hostname)

SSH_OPTS="-p $GIGABYTE1_PORT -i $GIGABYTE1_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=5"

while true; do
  cd "$REPO"

  # Push local corpus → gigabyte1 (hub collects and enriches)
  rsync -az \
    -e "ssh $SSH_OPTS" \
    simulation/corpus_p5/ \
    a1oleg@${GIGABYTE1_IP}:/home/a1oleg/tonGraph/simulation/corpus_p5/ \
    2>/dev/null

  # Pull enriched corpus ← gigabyte1
  rsync -az \
    -e "ssh $SSH_OPTS" \
    a1oleg@${GIGABYTE1_IP}:/home/a1oleg/tonGraph/simulation/corpus_p5/ \
    simulation/corpus_p5/ \
    2>/dev/null

  # Статистика
  FUZZ_STAT=$(grep -o 'cov: [0-9]* ft: [0-9]* corp: [0-9]*.*oom/timeout/crash: [0-9]*/[0-9]*/[0-9]*' "$FUZZ_LOG" 2>/dev/null | tail -1)
  COV=$(echo "$FUZZ_STAT" | grep -o 'cov: [0-9]*' | awk '{print $2}')
  CORPUS_P5=$(ls "$REPO/simulation/corpus_p5/" 2>/dev/null | wc -l)
  FORKS=$(pgrep -c fuzz_pool 2>/dev/null || echo "?")

  echo "[$(date '+%H:%M:%S')] sync done ($MACHINE cov=${COV:-?} p5=$CORPUS_P5 forks=$FORKS)"

  sleep 180
done
