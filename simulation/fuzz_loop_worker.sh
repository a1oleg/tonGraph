#!/bin/bash
# Перезапускает fuzz_pool при краше. Аргумент: номер воркера.
WORKER=${1:-1}
REPO=/home/a1oleg/tonGraph
cd "$REPO"
mkdir -p simulation/corpus_local_clean simulation/crashes_p5_gigabyte

while true; do
  ./build-fuzz2/test/consensus/fuzz_pool \
    -artifact_prefix=simulation/crashes_p5_gigabyte/ \
    -max_total_time=3600 \
    -max_len=4096 \
    simulation/corpus_local_clean \
    >> simulation/fuzz_local_worker${WORKER}.log 2>&1
  echo "[$(date '+%H:%M:%S')] worker $WORKER restarted (exit=$?)" \
    >> simulation/fuzz_local_worker${WORKER}.log
done
