#!/bin/bash
# Corpus orchestrator — runs on gigabyte1 (hub)
# Cycle every 2 min:
#   1. pull raw corpus from yoga1 + machine3 into staging
#   2. merge+minimize staging → corpus_fuzz_pool
#   3. archive new crashes to known_crashes/ (NOT merged into corpus)
#   4. push enriched corpus_fuzz_pool back to yoga1 + machine3

REPO=/home/a1oleg/tonGraph
FUZZ_POOL=$REPO/build-fuzz2/test/consensus/fuzz_pool
FUZZ_LOG=$REPO/simulation/fuzz_p5.log
MACHINE=$(hostname)

YOGA1_IP=192.168.10.115
YOGA1_PORT=2223
YOGA1_KEY=~/.ssh/yoga1_key

MACHINE3_IP=192.168.10.102
MACHINE3_PORT=2222
MACHINE3_KEY=~/.ssh/yoga1_key

SSH_YOGA1="ssh -p $YOGA1_PORT -i $YOGA1_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=5"
SSH_M3="ssh -p $MACHINE3_PORT -i $MACHINE3_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=5"

merge_dir() {
  local dst=$1; shift
  local sources=("$@")
  local tmp=$REPO/simulation/_merge_tmp
  mkdir -p "$tmp"
  "$FUZZ_POOL" -merge=1 "$tmp" "$dst" "${sources[@]}" 2>/dev/null || true
  if [ "$(ls -A "$tmp" 2>/dev/null)" ]; then
    mv "$tmp"/* "$dst"/
  fi
  rmdir "$tmp" 2>/dev/null || true
}

while true; do
  cd "$REPO"

  STAGING=$REPO/simulation/_staging
  mkdir -p "$STAGING"

  # 1. Pull worker corpus from spokes into staging
  #    Workers write to corpus_local_clean — that's where new coverage lives.
  rsync -az -e "$SSH_YOGA1" \
    a1oleg@${YOGA1_IP}:/home/a1oleg/tonGraph/simulation/corpus_local_clean/ \
    "$STAGING/" 2>/dev/null

  rsync -az -e "$SSH_M3" \
    a1oleg@${MACHINE3_IP}:~/tonGraph/simulation/corpus_local_clean/ \
    "$STAGING/" 2>/dev/null

  # Also include hub's own worker output
  rsync -a simulation/corpus_local_clean/ "$STAGING/" 2>/dev/null

  # 2. Merge+minimize staging → corpus_fuzz_pool (dedup, keep coverage-expanding only)
  if [ "$(ls -A "$STAGING" 2>/dev/null)" ]; then
    merge_dir simulation/corpus_fuzz_pool "$STAGING"
    rm -rf "$STAGING"
  fi

  # 3. Archive new crashes to known_crashes/ (do NOT merge into corpus — crash-seeds
  #    cause immediate worker restarts and only reproduce already-known bugs).
  CRASH_STAMP=$REPO/simulation/.crashes_merged_stamp
  CRASH_DIR=$REPO/simulation/crashes_p5_gigabyte
  KNOWN_DIR=$REPO/simulation/known_crashes
  mkdir -p "$KNOWN_DIR"

  if [ -f "$CRASH_STAMP" ]; then
    find "$CRASH_DIR" -newer "$CRASH_STAMP" -type f 2>/dev/null | \
      head -100 | xargs -I{} cp -n {} "$KNOWN_DIR/" 2>/dev/null
  else
    find "$CRASH_DIR" -type f 2>/dev/null | \
      head -100 | xargs -I{} cp -n {} "$KNOWN_DIR/" 2>/dev/null
  fi
  touch "$CRASH_STAMP"

  # 4. Push enriched corpus back to spokes' worker corpus (corpus_local_clean)
  #    Workers pick up new files on next run automatically.
  rsync -az -e "$SSH_YOGA1" \
    simulation/corpus_fuzz_pool/ \
    a1oleg@${YOGA1_IP}:/home/a1oleg/tonGraph/simulation/corpus_local_clean/ \
    2>/dev/null

  rsync -az -e "$SSH_M3" \
    simulation/corpus_fuzz_pool/ \
    a1oleg@${MACHINE3_IP}:~/tonGraph/simulation/corpus_local_clean/ \
    2>/dev/null

  # Also enrich hub's own worker corpus
  rsync -a simulation/corpus_fuzz_pool/ simulation/corpus_local_clean/ 2>/dev/null

  # 5. Статистика
  FUZZ_STAT=$(grep -o 'cov: [0-9]* ft: [0-9]* corp: [0-9]*.*oom/timeout/crash: [0-9]*/[0-9]*/[0-9]*' "$FUZZ_LOG" 2>/dev/null | tail -1)
  COV=$(echo "$FUZZ_STAT" | grep -o 'cov: [0-9]*' | awk '{print $2}')
  CORPUS_P5=$(ls "$REPO/simulation/corpus_fuzz_pool/" 2>/dev/null | wc -l)
  FORKS=$(pgrep -c fuzz_pool 2>/dev/null || echo "?")

  echo "[$(date '+%H:%M:%S')] orchestrate done ($MACHINE cov=${COV:-?} p5=$CORPUS_P5 forks=$FORKS)"

  sleep 180
done
