# Синхронизация corpus через GitHub (Phase 5)

Каждая машина фаззит независимо, мержит лучшие входы из локального `corpus_p5`
в трекаемый `corpus_p4a`, пушит в GitHub каждые 10 минут, пуллит прогресс другой.

**Ветка:** `testnet`
**Репо:** `a1oleg/tonGraph`

- **Машина 1** (главная) — стратегия wide: `run_fuzz_p5.sh`
- **Машина 2** (yoga1) — стратегия deep: `run_fuzz_p5_yoga.sh` (`-mutate_depth=8 -max_len=200`)

Shared corpus: `simulation/corpus_p4a/` (git-tracked)
Local corpus:  `simulation/corpus_p5/` (gitignored, растёт быстро)

---

## Машина 1 — уже запущена

Ничего дополнительно делать не нужно. Добавить sync-скрипт если ещё не запущен:

```bash
cd ~/tonGraph
tmux new-session -d -s sync_p5 "bash simulation/scripts/sync_p5.sh"
```

---

## Машина 2 (yoga1) — первоначальная настройка

### 1. Получить свежий код с seeds

```bash
cd ~/tonGraph
git pull origin testnet
```

### 2. Собрать fuzz_pool с ValidationRequest Accept фиксом

```bash
cmake -B build-fuzz2 \
  -DCMAKE_C_COMPILER=clang-18 -DCMAKE_CXX_COMPILER=clang++-18 \
  -DFUZZING=ON -G Ninja
cmake --build build-fuzz2 --target fuzz_pool -- -j$(nproc)
```

### 3. Запустить fuzzer (стратегия deep)

```bash
cd ~/tonGraph
chmod +x simulation/run_fuzz_p5_yoga.sh
mkdir -p simulation/corpus_p5
bash simulation/run_fuzz_p5_yoga.sh
```

### 4. Запустить sync-скрипт (раз в 10 мин)

```bash
chmod +x simulation/scripts/sync_p5.sh
tmux new-session -d -s sync_p5 "bash simulation/scripts/sync_p5.sh"
```

---

## Мониторинг

```bash
# Coverage (обе машины):
grep "cov:" simulation/fuzz_p5.log | tail -1

# Сколько файлов в shared corpus:
ls simulation/corpus_p4a/ | wc -l

# Sync лог:
tmux attach -t sync_p5
```

---

## Как работает синхронизация

```
Машина 1                          Машина 2 (yoga1)
---------                          ----------------
corpus_p5 (local)                  corpus_p5 (local)
     │                                   │
     ▼ merge                             ▼ merge
corpus_p4a ──── git push ──────► corpus_p4a
corpus_p4a ◄─── git pull ────────
```

1. Каждые 10 мин: `fuzz_pool -merge=1 corpus_p4a_tmp corpus_p4a corpus_p5`
2. Новые интересные входы → `corpus_p4a` → `git push origin testnet`
3. `git pull` → получаем прогресс другой машины
4. Fuzzer на следующей итерации подхватывает новые файлы из `corpus_p4a`

---

## Примечания

- `corpus_p4a/` трекается git — не кладём туда крашащие inputs вручную
- `corpus_p5/` gitignored — пусть растёт неограниченно
- crashes в `/tmp/fuzz_crashes_p5/` — gitignored; воспроизводить вручную
- При конфликте `git pull --rebase` предпочтительнее merge (corpus-файлы независимы)
