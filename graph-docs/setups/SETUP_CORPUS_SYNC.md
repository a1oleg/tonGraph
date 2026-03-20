# Синхронизация corpus через GitHub (Phase 4)

Каждая машина фаззит независимо, пушит свой corpus в GitHub каждые 10 минут,
пуллит corpus другой машины и делает `-merge`. Rsync по SSH не нужен.

**Ветка:** `testnet`
**Репо:** `a1oleg/tonGraph`

- **Машина 1** (главная) — `simulation/corpus_p4a/`
- **Машина 2** (yoga1) — `simulation/corpus_p4b/`

---

## Первоначальная настройка

### Машина 1

```bash
cd ~/tonGraph
mkdir -p simulation/corpus_p4a simulation/crashes_p4a
cp alarm_skip_seed_p4 simulation/corpus_p4a/
git add simulation/corpus_p4a/
git commit -m "corpus p4a: initial seed"
git push origin testnet
```

### Машина 2

```bash
cd ~/tonGraph
git pull origin testnet
mkdir -p simulation/corpus_p4b simulation/crashes_p4b
# Взять seed и corpus машины 1 как стартовый corpus:
cp simulation/corpus_p4a/* simulation/corpus_p4b/
git add simulation/corpus_p4b/
git commit -m "corpus p4b: initial seed from machine 1"
git push origin testnet
```

---

## Запуск фаззинга

### Машина 1 — стратегия A (широкий поиск)

```bash
REPO=~/tonGraph
tmux new-session -d -s fuzz_p4a \
  "cd $REPO && ./build-fuzz2/test/consensus/fuzz_pool \
   $REPO/simulation/corpus_p4a/ \
   -use_value_profile=1 \
   -jobs=$(nproc) \
   -artifact_prefix=$REPO/simulation/crashes_p4a/ \
   >> $REPO/simulation/fuzz_p4a.log 2>&1"
```

### Машина 2 — стратегия B (глубокие цепочки)

```bash
REPO=~/tonGraph
tmux new-session -d -s fuzz_p4b \
  "cd $REPO && ./build-fuzz2/test/consensus/fuzz_pool \
   $REPO/simulation/corpus_p4b/ \
   -use_value_profile=1 \
   -mutate_depth=8 -max_len=200 \
   -jobs=$(nproc) \
   -artifact_prefix=$REPO/simulation/crashes_p4b/ \
   >> $REPO/simulation/fuzz_p4b.log 2>&1"
```

---

## Sync-скрипт (раз в 10 минут)

Запустить в отдельном tmux-окне на каждой машине.

### Машина 1

```bash
cat > ~/tonGraph/simulation/scripts/sync_p4a.sh << 'EOF'
#!/bin/bash
set -e
REPO=~/tonGraph
BRANCH=testnet

while true; do
  cd $REPO

  # Запушить новые файлы своего corpus
  git add simulation/corpus_p4a/ 2>/dev/null
  if ! git diff --cached --quiet; then
    git commit -m "corpus p4a sync $(date '+%H:%M')"
    git push origin $BRANCH
  fi

  # Забрать corpus машины 2
  git pull --rebase origin $BRANCH 2>/dev/null || git pull origin $BRANCH

  # Merge corpus p4b в p4a
  if [ -d simulation/corpus_p4b ] && [ "$(ls -A simulation/corpus_p4b)" ]; then
    mkdir -p simulation/corpus_p4a_merged
    ./build-fuzz2/test/consensus/fuzz_pool -merge=1 \
      simulation/corpus_p4a_merged/ \
      simulation/corpus_p4a/ \
      simulation/corpus_p4b/ \
      2>/dev/null
    if [ "$(ls -A simulation/corpus_p4a_merged)" ]; then
      mv simulation/corpus_p4a_merged/* simulation/corpus_p4a/
    fi
    rmdir simulation/corpus_p4a_merged 2>/dev/null || true
  fi

  echo "[$(date '+%H:%M:%S')] sync done"
  sleep 600
done
EOF
chmod +x ~/tonGraph/simulation/scripts/sync_p4a.sh
tmux new-session -d -s sync_p4a "~/tonGraph/simulation/scripts/sync_p4a.sh"
```

### Машина 2

```bash
cat > ~/tonGraph/simulation/scripts/sync_p4b.sh << 'EOF'
#!/bin/bash
set -e
REPO=~/tonGraph
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
EOF
chmod +x ~/tonGraph/simulation/scripts/sync_p4b.sh
tmux new-session -d -s sync_p4b "~/tonGraph/simulation/scripts/sync_p4b.sh"
```

---

## Мониторинг

```bash
# Статус фаззинга (на каждой машине):
for i in $(seq 0 $(($(nproc)-1))); do
  ft=$(grep -oP 'ft: \K[0-9]+' fuzz-$i.log 2>/dev/null | tail -1)
  cov=$(grep -oP 'cov: \K[0-9]+' fuzz-$i.log 2>/dev/null | tail -1)
  echo "worker-$i: cov=$cov ft=$ft"
done

# Крашей нет?
ls ~/tonGraph/simulation/crashes_p4a/   # машина 1
ls ~/tonGraph/simulation/crashes_p4b/   # машина 2
```

---

## Если найден краш

```bash
# Остановить фаззинг
tmux kill-session -t fuzz_p4a   # или fuzz_p4b

# Воспроизвести
./build-fuzz2/test/consensus/fuzz_pool simulation/crashes_p4a/crash-* 2>&1
echo "exit: $?"
# exit 77 = __builtin_trap() = alarm-skip-after-notarize confirmed
```

---

## Примечания

- `corpus_p4a/` и `corpus_p4b/` трекаются git; crashes и logs — в `.gitignore`
- При конфликте `git pull --rebase` предпочтительнее merge (corpus-файлы независимы)
- Если `fuzz_pool` найдёт alarm-skip crash и запишет в `crashes_p4*/` — sync-скрипт
  его не пушит (папка в `.gitignore`). Краш воспроизвести вручную и задокументировать.
