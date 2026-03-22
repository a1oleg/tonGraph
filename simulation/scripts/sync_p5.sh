#!/bin/bash
# Usage: bash sync_p5.sh [PARITY]
#   PARITY=1 (default) — sync on odd minutes  (машина 1)
#   PARITY=0           — sync on even minutes (yoga1)
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

# Функция: sleep до :00 следующей минуты с нужной чётностью
# $1=0: начальный вызов (можно войти в текущее окно)
# $1=1: после цикла (всегда идём на следующую свою минуту)
wait_for_slot() {
  local now m next after_cycle=${1:-0}
  now=$(date +%s)
  m=$(( now / 60 ))
  if (( after_cycle == 0 && m % 2 == PARITY && now % 60 < 30 )); then
    return  # начальный запуск — уже в своём окне
  elif (( m % 2 == PARITY )); then
    next=$(( (m + 2) * 60 ))  # текущая минута своя — берём следующую через одну
  else
    next=$(( (m + 1) * 60 ))  # не своя — берём ближайшую свою
  fi
  sleep $(( next - now ))
}

# Начальный wait — первый запуск тоже попадает в своё окно
wait_for_slot

while true; do
  cd $REPO

  # Собрать статистику фаззера
  FUZZ_STAT=$(grep -o 'cov: [0-9]* ft: [0-9]* corp: [0-9]*.*oom/timeout/crash: [0-9]*/[0-9]*/[0-9]*' "$FUZZ_LOG" 2>/dev/null | tail -1)
  COV=$(echo "$FUZZ_STAT" | grep -o 'cov: [0-9]*' | awk '{print $2}')
  CORP=$(echo "$FUZZ_STAT" | grep -o 'corp: [0-9]*' | awk '{print $2}')
  CRASHES=$(echo "$FUZZ_STAT" | grep -o 'crash: [0-9]*' | awk '{print $2}')
  CORPUS_P5=$(ls "$REPO/simulation/corpus_p5/" 2>/dev/null | wc -l)
  CORPUS_P4A=$(ls "$REPO/simulation/corpus_p4a/" 2>/dev/null | wc -l)

  # Билд: git commit fuzz_pool.cpp + дата бинаря + максимальный vtype + fork count
  BUILD_COMMIT=$(git log -1 --format="%h" -- test/consensus/fuzz_pool.cpp 2>/dev/null)
  BUILD_DATE=$(stat -c "%y" "$REPO/build-fuzz2/test/consensus/fuzz_pool" 2>/dev/null | cut -c1-16)
  MAX_VTYPE=$(grep 'vote_type = fdp.ConsumeIntegralInRange' "$REPO/test/consensus/fuzz_pool.cpp" 2>/dev/null | grep -o '[0-9]*);' | tr -d ');' || true)
  FORKS=$(pgrep -c fuzz_pool 2>/dev/null || echo "?")

  # Дописать отчёт
  echo "[$(date '+%Y-%m-%d %H:%M')] $MACHINE: cov=${COV:-?} corp=${CORP:-?} p5=$CORPUS_P5 p4a=$CORPUS_P4A crashes=${CRASHES:-?} | build=$BUILD_COMMIT $BUILD_DATE vtype_max=${MAX_VTYPE:-?} forks=$FORKS" >> "$REPORT"

  # Запушить corpus + отчёт + любые изменения в коде (fuzz_pool.cpp, mutator, etc.)
  # git add -u: все tracked файлы с изменениями (не оставляет modified unstaged)
  git add -u 2>/dev/null
  git add simulation/corpus_p5/ contest/setups/sync_report.md \
    test/consensus/ validator/consensus/ simulation/scripts/ \
    minimized-from-* 2>/dev/null
  if ! git diff --cached --quiet; then
    git commit -m "corpus p5 sync $(date '+%H:%M')"
  fi

  # Забрать corpus машины 1 (до push — чтобы избежать rejected)
  # stash push/pop только для untracked-like изменений; при конфликте pop — дропаем стэш
  # чтобы не накапливать conflict markers в tracked файлах.
  git stash push -q 2>/dev/null || true
  git pull --rebase origin $BRANCH 2>/dev/null || git pull origin $BRANCH
  git stash pop -q 2>/dev/null || git stash drop -q 2>/dev/null || true
  # Если после pop остались conflict markers — сбросить файл до HEAD
  if git diff --name-only | xargs grep -l "^<<<<<<" 2>/dev/null | grep -q .; then
    git diff --name-only | xargs grep -l "^<<<<<<" | xargs git checkout HEAD -- 2>/dev/null || true
  fi

  # Push с retry: если rejected (другая машина успела), тянем и пробуем ещё раз
  for _retry in 1 2 3; do
    git push origin $BRANCH && break
    git stash push -q 2>/dev/null || true
    git pull --rebase origin $BRANCH 2>/dev/null || git pull origin $BRANCH
    git stash pop -q 2>/dev/null || git stash drop -q 2>/dev/null || true
  done

  # Merge corpus p4a в p5
  if [ -d simulation/corpus_p4a ] && [ "$(ls -A simulation/corpus_p4a)" ]; then
    mkdir -p simulation/corpus_p5_merged
    ./build-fuzz2/test/consensus/fuzz_pool -merge=1 \
      simulation/corpus_p5_merged/ \
      simulation/corpus_p5/ \
      simulation/corpus_p4a/ \
      2>/dev/null || true
    if [ "$(ls -A simulation/corpus_p5_merged)" ]; then
      mv simulation/corpus_p5_merged/* simulation/corpus_p5/
    fi
    rmdir simulation/corpus_p5_merged 2>/dev/null || true
  fi

  echo "[$(date '+%H:%M:%S')] sync p5 done ($MACHINE cov=${COV:-?})"

  # Sleep до следующего своего окна
  wait_for_slot 1
done
