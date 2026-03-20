# Фаззинг — Phase 4: распределённый запуск

[← Phase 3](FUZZING_PHASE3.md) | [Общий план](FUZZING_PLAN.md)

## Контекст

Phase 3 завершена: `cov: 854, ft: 3162, крашей: 0`.
alarm-skip-after-notarize случайным мутатором за 1.5 часа не найден.

**Phase 4 Step 02 (фикс):** `n_pre` поднят с 7 до 15 — `slots_per_leader_window=4`
требует ≥12 pre-crash голосов чтобы `first_nonannounced_window` вышел за 0
и ConsensusImpl при restart начал слать SkipVote.

**Phase 4 Step 1 (фикс harness):** Scheduler изменён с `NodeInfo{{1}}` на `NodeInfo{{0}}` —
без этого акторы выполнялись в фоновом CPU-треде асинхронно, harness был не детерминирован.
Подробнее: раздел «Шаг 1 → Исправление: NodeInfo{{0}}».
2
---

## Текущий прогресс

```
Шаг 0  ✅  n_pre 7→15 (slots_per_leader_window=4 требует ≥12 pre-crash голосов)
Шаг 1  ✅  Targeted seed — alarm-skip PoC подтверждён (exit 77 / SIGTRAP)
Шаг 2  🔄  Запуск: Главный (стратегия A) запущен; Второй (стратегия B) — настройка
Шаг 3  🔲  Координатор (если 72ч без краша)
```

---

## Шаг 1 — Targeted seed для alarm-skip ✅

**Статус:** PoC подтверждён. `alarm_skip_seed_p4` вызывает `SIGTRAP`, exit code 77.

### Исправление: NodeInfo{{0}} (критично для harness)

Harness использовал `NodeInfo{{1}}` → создавался фоновый CPU-поток для акторов.
`run(0)` тикает только IO-очередь, CPU-актор обрабатывался в фоне **асинхронно** —
Pool, MockDb, FuzzObserver выполнялись на фоновом треде параллельно с `inject_vote`.
Следствие: harness не детерминирован, `handle_certificate` завершался после рестарта.

**Фикс:** `NodeInfo{{0}}` — ноль CPU-тредов. В `add_to_queue`:
`!info.cpu_queue → true` → все акторы идут в IO-очередь → `run(0)` обрабатывает
их синхронно на главном треде. Каждый `inject_vote` с 20 раундами дрейна полностью
завершает цепочку `handle_certificate` → `SaveCertificate` → `NotarizationObserved`.

### Фактический механизм alarm-skip

```
Pre-crash (n_pre=12):
  slot 0-3: notarize от val 0,1,2 × 4 слота = 12 голосов
  → 4 NotarCert записаны в MockDb; FuzzObserver: g_notar_by_slot={0,1,2,3}
  → pool_state.first_nonannounced_window=1 записан в WAL

Crash (n_lose=1):
  → теряем запись pool_state (window=1 → откатывается до initial=0)
  → NotarCert'ы в DB сохранены (записывались раньше)

Restart:
  → Pool загружает 4 NotarCert из DB, bootstrap пересчитывает window=1
  → публикует LeaderWindowObserved{start_slot=4}
  → ConsensusImpl получает событие, автоматически рассылает SkipVote{0,1,2,3}
  → SkipVote{3} от val 0 (ConsensusImpl) + inject val 1 + inject val 2 = 3/4 quorum

Post-crash (n_post=2):
  slot 3: SkipVote от val 1, SkipVote от val 2
  → quorum: ConsensusImpl(val 0) + val 1 + val 2 = 3/4 → SkipCert{3}
  → FuzzObserver: g_notar_by_slot.count(3)=1 → __builtin_trap() 💥
```

### Seed файл

`alarm_skip_seed_p4` (60 байт, подтверждён):
```
hex: 00030102 00030101 00030002 00030001 00030000
     00020002 00020001 00020000 00010002 00010001
     00010000 00000002 00000001 00000000 0201010c
```

**Примечание о FDP byte order:** `FuzzedDataProvider` читает байты с конца буфера.
Последние 4 байта (`02 01 01 0c`) = управляющие: n_post=2, n_lose=1, do_crash=1, n_pre=12.
Сообщения лежат в начале файла в обратном порядке (последнее сообщение — первые байты).
Каждая группа из 4 байт тоже reversed: [cand, slot, vtype, src] в файле → FDP читает [src, vtype, slot, cand].

Сгенерировать:

```bash
python3 - <<'EOF'
def encode_vote_for_fdp(src, vote_type, slot, cand_seed=0):
    # FDP читает [src, vtype, slot, cand] с конца — байты в файле reversed
    return bytes([cand_seed, slot, vote_type, src])

pre_msgs = []
for slot in range(4):
    for src in [0, 1, 2]:
        pre_msgs.append(encode_vote_for_fdp(src, 0, slot))  # notarize

post_msgs = [
    encode_vote_for_fdp(1, 1, 3),  # SkipVote slot=3, val 1
    encode_vote_for_fdp(2, 1, 3),  # SkipVote slot=3, val 2
]

# Сообщения в файле: reversed(post) затем reversed(pre)
# (FDP читает с конца → первое pre-сообщение читается последним из pre)
seed = b''
for m in reversed(post_msgs):
    seed += m
for m in reversed(pre_msgs):
    seed += m
# FDP-контроль в конце: [n_post, n_lose, do_crash, n_pre] (reversed порядок чтения)
seed += bytes([2, 1, 1, 12])

with open('alarm_skip_seed_p4', 'wb') as f:
    f.write(seed)
print(f"Written {len(seed)} bytes:", seed.hex())
EOF

# Запустить — должен упасть с SIGTRAP (exit 77):
./build-fuzz2/test/consensus/fuzz_pool alarm_skip_seed_p4 2>/dev/null
echo "exit code: $?"
```

**Результат:** exit code 77 (SIGTRAP) ✅ — alarm-skip PoC подтверждён.

---

## Шаг 2 — Запуск двух машин

После подтверждения пути — масштабировать. Seed добавляется в corpus обеих машин.

### Главный (машина 1)

Широкий поиск с cosine similarity guidance. Даёт наибольший `ft` по результатам
пробного запуска (ft: 3162 против 3132 у стратегии B).

```bash
REPO=$(pwd)
mkdir -p simulation/corpus_p4a simulation/crashes_p4a

# Примечание: alarm_skip_seed_p4 — это крашащий input, НЕ кладём его в corpus.
# Fuzzer сам найдёт alarm-skip через мутации от corpus_p3s3.

tmux new-session -d -s fuzz_p4a \
  "cd $REPO && ./build-fuzz2/test/consensus/fuzz_pool \
   $REPO/simulation/corpus_p3s3/ \
   $REPO/simulation/corpus_p4a/ \
   -use_value_profile=1 \
   -fork=$(nproc) -ignore_crashes=1 \
   -artifact_prefix=$REPO/simulation/crashes_p4a/ \
   >> $REPO/simulation/fuzz_p4a.log 2>&1"
```

**Почему `-fork` вместо `-jobs`:** libFuzzer не устанавливает обработчик SIGTRAP.
При `__builtin_trap()` в воркере с `-jobs`, координатор умирает вместе с воркером.
`-fork=N -ignore_crashes=1` запускает N постоянных суб-процессов; при крашe воркера
координатор продолжает, записывает артефакт, запускает новый fork.

**Corpus sync — раз в час:**
```bash
MACHINE2=user@machine2

rsync -az $MACHINE2:~/tonGraph/simulation/corpus_p4b/ \
         ~/tonGraph/simulation/corpus_p4b_remote/
./build-fuzz2/test/consensus/fuzz_pool -merge=1 \
  ~/tonGraph/simulation/corpus_p4a_merged/ \
  ~/tonGraph/simulation/corpus_p4a/ \
  ~/tonGraph/simulation/corpus_p4b_remote/
mv ~/tonGraph/simulation/corpus_p4a_merged/* \
   ~/tonGraph/simulation/corpus_p4a/
```

**На что смотреть:**
```bash
tail -3 fuzz-0.log          # cov, ft, exec/s
ls simulation/crashes_p4a/  # любой файл = alarm-skip найден → стоп
```

---

### Второй (машина 2)

Глубокие цепочки с ограничением длины. Находит короткие воспроизводимые пути
к quorum-сценариям, которые стратегия A пропускает.

```bash
REPO=$(pwd)
mkdir -p simulation/corpus_p4b simulation/crashes_p4b

# Первый запуск: скопировать seed-corpus с главного
MACHINE1=user@machine1
rsync -az $MACHINE1:~/tonGraph/simulation/corpus_p3s3/ \
         ~/tonGraph/simulation/corpus_p3s3/
rsync -az $MACHINE1:~/tonGraph/alarm_skip_seed_p4 \
         ~/tonGraph/simulation/corpus_p4b/

tmux new-session -d -s fuzz_p4b \
  "cd $REPO && ./build-fuzz2/test/consensus/fuzz_pool \
   $REPO/simulation/corpus_p3s3/ \
   $REPO/simulation/corpus_p4b/ \
   -use_value_profile=1 \
   -mutate_depth=8 -max_len=200 \
   -jobs=$(nproc) \
   -artifact_prefix=$REPO/simulation/crashes_p4b/ \
   >> $REPO/simulation/fuzz_p4b.log 2>&1"
```

**Corpus sync — раз в час:**
```bash
MACHINE1=user@machine1

rsync -az $MACHINE1:~/tonGraph/simulation/corpus_p4a/ \
         ~/tonGraph/simulation/corpus_p4a_remote/
./build-fuzz2/test/consensus/fuzz_pool -merge=1 \
  ~/tonGraph/simulation/corpus_p4b_merged/ \
  ~/tonGraph/simulation/corpus_p4b/ \
  ~/tonGraph/simulation/corpus_p4a_remote/
mv ~/tonGraph/simulation/corpus_p4b_merged/* \
   ~/tonGraph/simulation/corpus_p4b/
```

---

### Если машина 2 отвалилась и вернулась

```bash
MACHINE1=user@machine1

# 1. Забрать актуальный corpus с главного
rsync -az $MACHINE1:~/tonGraph/simulation/corpus_p4a/ \
         ~/tonGraph/simulation/corpus_p4a_remote/

# 2. Merge
./build-fuzz2/test/consensus/fuzz_pool -merge=1 \
  ~/tonGraph/simulation/corpus_p4b_merged/ \
  ~/tonGraph/simulation/corpus_p4b/ \
  ~/tonGraph/simulation/corpus_p4a_remote/
mv ~/tonGraph/simulation/corpus_p4b_merged/* \
   ~/tonGraph/simulation/corpus_p4b/

# 3. Перезапустить
tmux new-session -d -s fuzz_p4b \
  "cd ~/tonGraph && ./build-fuzz2/test/consensus/fuzz_pool \
   ~/tonGraph/simulation/corpus_p3s3/ \
   ~/tonGraph/simulation/corpus_p4b/ \
   -use_value_profile=1 \
   -mutate_depth=8 -max_len=200 \
   -jobs=$(nproc) \
   -artifact_prefix=~/tonGraph/simulation/crashes_p4b/ \
   >> ~/tonGraph/simulation/fuzz_p4b.log 2>&1"
```

---

## Шаг 3 — Координатор (если 72ч без краша)

Будет описан отдельно после получения результатов Шагов 1–2.

Идея: Redis как очередь целей — каждый воркер получает назначение «покрой этот базовый блок»,
не дублирует уже покрытое. Реализация: `LLVMFuzzerCustomMutator` + Redis-клиент.

---

## Критерии перехода

| Сигнал | Действие |
|---|---|
| Шаг 1: seed вызвал SIGTRAP | PoC подтверждён → Шаг 2 (масштабирование) |
| Шаг 1: seed не упал | Отладить harness → найти почему path не достигнут |
| `crashes_p4*/` не пустой | Стоп все. Воспроизвести вручную, записать PoC |
| 24ч без краша, ft растёт | corpus merge + продолжить |
| 72ч без краша | Перейти к Шагу 3 (координатор) |

---

## Диагностика

```bash
# Быстрая сводка по всем воркерам:
for i in $(seq 0 $(($(nproc)-1))); do
  ft=$(grep -oP 'ft: \K[0-9]+' fuzz-$i.log 2>/dev/null | tail -1)
  cov=$(grep -oP 'cov: \K[0-9]+' fuzz-$i.log 2>/dev/null | tail -1)
  echo "worker-$i: cov=$cov ft=$ft"
done

# Сравнить ft между машинами (выполнить на главном):
echo "=== Главный ===" && tail -2 ~/tonGraph/fuzz-0.log
ssh $MACHINE2 "echo '=== Второй ===' && tail -2 ~/tonGraph/fuzz-0.log"
```
