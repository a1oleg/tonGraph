# Фаззинг — Phase 4: распределённый запуск

[← Phase 3](FUZZING_PHASE3.md) | [Общий план](FUZZING_PLAN.md)

## Контекст

Phase 3 завершена: `cov: 854, ft: 3162, крашей: 0`.
alarm-skip-after-notarize случайным мутатором за 1.5 часа не найден.
Цель Phase 4 — горизонтальное масштабирование и специализация стратегий.

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
Шаг 1  🔲  Запуск: Главный (стратегия A) + Второй (стратегия B)
Шаг 2  🔲  Targeted seed для alarm-skip (если 24ч без краша)
Шаг 3  🔲  Координатор (если 72ч без краша)
```

---

## Шаг 1 — Запуск двух машин

### Главный (машина 1)

Широкий поиск с cosine similarity guidance. Даёт наибольший `ft` по результатам
пробного запуска (ft: 3162 против 3132 у стратегии B).

```bash
REPO=$(pwd)
mkdir -p simulation/corpus_p4a simulation/crashes_p4a

tmux new-session -d -s fuzz_p4a \
  "cd $REPO && ./build-fuzz2/test/consensus/fuzz_pool \
   $REPO/simulation/corpus_p3s3/ \
   $REPO/simulation/corpus_p4a/ \
   -use_value_profile=1 \
   -jobs=$(nproc) \
   -artifact_prefix=$REPO/simulation/crashes_p4a/ \
   >> $REPO/simulation/fuzz_p4a.log 2>&1"
```

**Corpus sync — раз в час (cron или вручную):**
```bash
MACHINE2=user@machine2   # заменить на реальный адрес

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

**На что смотреть:**
```bash
tail -3 fuzz-0.log          # cov, ft, exec/s
ls simulation/crashes_p4b/  # любой файл = alarm-skip найден → стоп
```

---

### Если машина 2 отвалилась и вернулась

```bash
# На машине 2 после возврата:
MACHINE1=user@machine1

# 1. Забрать актуальный corpus с главного
rsync -az $MACHINE1:~/tonGraph/simulation/corpus_p4a/ \
         ~/tonGraph/simulation/corpus_p4a_remote/

# 2. Merge: своё старое + новое с главного
./build-fuzz2/test/consensus/fuzz_pool -merge=1 \
  ~/tonGraph/simulation/corpus_p4b_merged/ \
  ~/tonGraph/simulation/corpus_p4b/ \
  ~/tonGraph/simulation/corpus_p4a_remote/
mv ~/tonGraph/simulation/corpus_p4b_merged/* \
   ~/tonGraph/simulation/corpus_p4b/

# 3. Перезапустить — tmux-сессия уже убита, создать новую
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

## Шаг 2 — Targeted seed для alarm-skip (если 24ч без краша)

Точная последовательность которую случайный мутатор не находит:

```
n_pre=7:
  slot 0: notarize от validators 0,1,2  → NotarCert{0} → Pool объявляет LeaderWindow{1}
  slot 1: notarize от validators 0,1,2  → NotarCert{1} → LeaderWindow{2}
  slot 2: notarize от validators 0,1,2  → NotarCert{2} → LeaderWindow{3}
  slot 3: notarize от validators 0,1,2  → NotarCert{3} → LeaderWindow{4}
do_crash=1, n_lose=1                    → теряем ourVote{3} из WAL
n_post=2:
  slot 3: skip от validator 1
  slot 3: skip от validator 2
  → ConsensusImpl (наш узел) тоже шлёт SkipVote{3} → quorum 3/4 → SkipCert{3}
  → g_notar_by_slot[3] заполнен → __builtin_trap()
```

Сгенерировать байты и добавить в corpus обеих машин:

```bash
python3 - <<'EOF'
import struct, sys

def encode_vote(src, vote_type, slot, cand_seed):
    # 4 байта: src(2b) vote_type(2b) slot(8b) cand_seed(8b) — упаковка FuzzedDataProvider
    # FuzzedDataProvider::ConsumeIntegralInRange читает LE bytes
    return bytes([src, vote_type, slot, cand_seed])

msgs = []
# n_pre=7: notarize слоты 0-3 от трёх валидаторов (7 сообщений, slot3 от двух)
for slot in range(3):
    for src in [0, 1, 2]:
        msgs.append(encode_vote(src, 0, slot, 0))   # vote_type=0 = notarize
# slot 3 от двух валидаторов (третье — сам наш узел через ConsensusImpl)
msgs.append(encode_vote(1, 0, 3, 0))
msgs.append(encode_vote(2, 0, 3, 0))

# header: n_pre=7(0..7) do_crash=1 n_lose=1(0..8) n_post=2(0..7)
# FuzzedDataProvider раскодирует эти байты через ConsumeIntegralInRange
header = bytes([
    6,   # n_pre=7 → ConsumeIntegralInRange(0,7): raw byte 6 = 6 (mod 8 = 6 → не 7)
    # Проще: задаём напрямую нужные значения, harness сам клипает
    # n_pre: 7 → байт 7 (max range=7)
])
# Точнее: пишем как raw input который FDP разбирает
# n_pre = ConsumeIntegralInRange<uint8_t>(0,7) → потребляет 1 байт, map в [0,7]
# FDP использует ((byte % (max-min+1)) + min), т.е. byte % 8
# Чтобы получить 7: байт = 7
seed = bytes([7]) + bytes([1]) + bytes([1]) + bytes([2])
for m in msgs[:7]:
    seed += m
# n_post: skip slot=3 от validators 1 и 2
seed += encode_vote(1, 1, 3, 0)  # vote_type=1 = skip
seed += encode_vote(2, 1, 3, 0)

with open('alarm_skip_seed_p4', 'wb') as f:
    f.write(seed)
print(f"Written {len(seed)} bytes:", seed.hex())
EOF

cp alarm_skip_seed_p4 simulation/corpus_p4a/
cp alarm_skip_seed_p4 simulation/corpus_p4b/
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
| `crashes_p4*/` не пустой | Стоп все. Воспроизвести вручную, записать PoC |
| 24ч без краша, ft растёт | Добавить targeted seed (Шаг 2), продолжить |
| 24ч без краша, ft в плато | corpus merge + перезапуск с новыми seeds |
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
