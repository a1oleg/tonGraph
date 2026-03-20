# Фаззинг — Phase 4: распределённый запуск

[← Phase 3](FUZZING_PHASE3.md) | [Общий план](FUZZING_PLAN.md)

## Контекст

Phase 3 завершена: `cov: 854, ft: 3162, крашей: 0`.
alarm-skip-after-notarize случайным мутатором за 1.5 часа не найден.

**Phase 4 Step 0 (фикс):** `n_pre` поднят с 7 до 15 — `slots_per_leader_window=4`
требует ≥12 pre-crash голосов чтобы `first_nonannounced_window` вышел за 0
и ConsensusImpl при restart начал слать SkipVote.

---

## Принцип: слабая связь

Каждая машина **самодостаточна** — фаззит независимо и не падает если другая недоступна.
Связь — только через rsync corpus раз в час. Файлы corpus атомарны (libFuzzer пишет
новые файлы, не изменяет существующие), rsync идемпотентен.

**Если машина отвалилась:**
- Остальные продолжают без остановки
- При возврате: pull corpus, запустить merge, продолжить — потери только в итерациях
  за время простоя, не в corpus

---

## Текущий прогресс

```
Шаг 0  ✅  n_pre 7→15 (slots_per_leader_window=4 требует ≥12 pre-crash голосов)
Шаг 1  🔲  Targeted seed — подтвердить alarm-skip путь
Шаг 2  🔲  Запуск: Главный (стратегия A) + Второй (стратегия B)
Шаг 3  🔲  Координатор (если 72ч без краша)
```

---

## Шаг 1 — Targeted seed для alarm-skip

Точная последовательность которую случайный мутатор не находит.
Сначала подтвердить что `__builtin_trap()` срабатывает — затем масштабировать.

```
n_pre=12:
  slot 0: notarize от val 0,1,2  → NotarCert{0} → slot 0 notarized
  slot 1: notarize от val 0,1,2  → NotarCert{1} → slot 1 notarized
  slot 2: notarize от val 0,1,2  → NotarCert{2} → slot 2 notarized
  slot 3: notarize от val 0,1,2  → NotarCert{3} → slot 3 notarized
  → now_=4, first_nonannounced_window=1 → записывается в WAL
do_crash=1, n_lose=1             → теряем ourVote{3} из WAL
n_post=2:
  slot 3: SkipVote от val 1
  slot 3: SkipVote от val 2
  → ConsensusImpl (val 0) шлёт SkipVote{3} при restart (first_nonannounced_window > 0)
  → quorum 3/4 → SkipCert{3} + g_notar_by_slot[3] заполнен → __builtin_trap()
```

Сгенерировать и проверить:

```bash
python3 - <<'EOF'
def encode_vote(src, vote_type, slot, cand_seed=0):
    return bytes([src, vote_type, slot, cand_seed])

msgs = []
# n_pre=12: notarize слоты 0-3 от трёх валидаторов (4 слота × 3 = 12 сообщений)
for slot in range(4):
    for src in [0, 1, 2]:
        msgs.append(encode_vote(src, 0, slot))  # vote_type=0 = notarize

# FDP encoding: ConsumeIntegralInRange(0,15) → byte % 16
# n_pre=12: byte=12; do_crash=True: byte=1; n_lose=1: byte=1; n_post=2: byte=2
seed = bytes([12, 1, 1, 2])
for m in msgs:
    seed += m
# n_post: SkipVote slot=3 от val 1 и 2
seed += encode_vote(1, 1, 3)  # vote_type=1 = skip
seed += encode_vote(2, 1, 3)

with open('alarm_skip_seed_p4', 'wb') as f:
    f.write(seed)
print(f"Written {len(seed)} bytes:", seed.hex())
EOF

# Запустить одиночным входом — должен упасть с SIGTRAP:
./build-fuzz2/test/consensus/fuzz_pool alarm_skip_seed_p4
echo "exit code: $?"
```

**Если упал (exit ≠ 0):** alarm-skip подтверждён → это PoC, переходить к Шагу 2.
**Если не упал:** разобраться почему (добавить отладочный вывод в harness).

---

## Шаг 2 — Запуск двух машин

После подтверждения пути — масштабировать. Seed добавляется в corpus обеих машин.

### Главный (машина 1)

Широкий поиск с cosine similarity guidance. Даёт наибольший `ft` по результатам
пробного запуска (ft: 3162 против 3132 у стратегии B).

```bash
REPO=$(pwd)
mkdir -p simulation/corpus_p4a simulation/crashes_p4a

# Скопировать targeted seed в corpus
cp alarm_skip_seed_p4 simulation/corpus_p4a/

tmux new-session -d -s fuzz_p4a \
  "cd $REPO && ./build-fuzz2/test/consensus/fuzz_pool \
   $REPO/simulation/corpus_p3s3/ \
   $REPO/simulation/corpus_p4a/ \
   -use_value_profile=1 \
   -jobs=$(nproc) \
   -artifact_prefix=$REPO/simulation/crashes_p4a/ \
   >> $REPO/simulation/fuzz_p4a.log 2>&1"
```

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
