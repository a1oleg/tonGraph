#!/bin/bash
cd /home/a1oleg/tonGraph
mkdir -p simulation/crashes_p5_gigabyte
mkdir -p simulation/corpus_p5

for i in 1 2 3 4 5 6; do
  nohup ./build-fuzz2/test/consensus/fuzz_pool \
    -artifact_prefix=simulation/crashes_p5_gigabyte/ \
    -max_len=4096 \
    simulation/corpus_p5 \
    > simulation/fuzz_gigabyte_local_worker${i}.log 2>&1 &
  echo "worker $i pid=$!"
done
wait
