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
git pull origin testnet   # уже сделано, corpus_p4a пуст (крашащий seed убран)
mkdir -p simulation/corpus_p4a simulation/crashes_p4a
# corpus_p4a начинается пустым — fuzzer наполнит его сам через corpus_p3s3
```

### Машина 2

```bash
cd ~/tonGraph
git pull origin testnet
mkdir -p simulation/corpus_p4b simulation/crashes_p4b
# corpus_p4b тоже начинается пустым (синхронизируется через GitHub каждые 10 мин)
```

---

## Запуск фаззинга

### Машина 1 — стратегия A (широкий поиск)

```bash
REPO=~/tonGraph
mkdir -p simulation/corpus_p4a simulation/crashes_p4a
# Примечание: НЕ кладём alarm_skip_seed_p4 в corpus — это крашащий input.
tmux new-session -d -s fuzz_p4a \
  "cd $REPO && ./build-fuzz2/test/consensus/fuzz_pool \
   $REPO/simulation/corpus_p3s3/ \
   $REPO/simulation/corpus_p4a/ \
   -use_value_profile=1 \
   -fork=\$(nproc) -ignore_crashes=1 \
   -artifact_prefix=$REPO/simulation/crashes_p4a/ \
   >> $REPO/simulation/fuzz_p4a.log 2>&1"
```

> **Почему `-fork` вместо `-jobs`:** libFuzzer не обрабатывает SIGTRAP (от
> `__builtin_trap()`). С `-jobs=N` SIGTRAP в воркере убивает координатора.
> `-fork=N -ignore_crashes=1` — воркер крашится, координатор продолжает.

### Машина 2 — стратегия B (глубокие цепочки)

```bash
REPO=~/tonGraph
mkdir -p simulation/corpus_p4b simulation/crashes_p4b
git pull origin testnet   # взять corpus_p4a от машины 1
tmux new-session -d -s fuzz_p4b \
  "cd $REPO && ./build-fuzz2/test/consensus/fuzz_pool \
   $REPO/simulation/corpus_p3s3/ \
   $REPO/simulation/corpus_p4b/ \
   -use_value_profile=1 \
   -fork=\$(nproc) -ignore_crashes=1 \
   -mutate_depth=8 -max_len=200 \
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
# Статус фаззинга (fork-mode — лог общий):
tail -f ~/tonGraph/simulation/fuzz_p4a.log   # машина 1
tail -f ~/tonGraph/simulation/fuzz_p4b.log   # машина 2

# Краткая сводка: coverage, exec/s, кол-во крашей:
grep "cov:" ~/tonGraph/simulation/fuzz_p4a.log | tail -1

# Количество найденных крашей:
ls ~/tonGraph/simulation/crashes_p4a/ | wc -l   # машина 1
ls ~/tonGraph/simulation/crashes_p4b/ | wc -l   # машина 2
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
