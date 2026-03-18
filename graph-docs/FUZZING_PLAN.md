# Фаззинг simplex consensus — план

## Статус реализации

| Компонент | Статус |
|---|---|
| `simulation/fuzz_harness.cpp` | ✅ [54933808](https://github.com/a1oleg/tonGraph/commit/54933808) — FuzzedDataProvider (fuzzer) + FuzzReader (standalone) |
| `simulation/corpus_fuzz/` | ✅ 272 targeted seed (4 уязвимости, полное покрытие Pre(k)) |
| `simulation/scripts/gen_targeted_corpus.py` | ✅ [5aa6dab6](https://github.com/a1oleg/tonGraph/commit/5aa6dab6) — backwards reachability generator |
| `build-fuzz/simulation/fuzz_harness` | ✅ libFuzzer бинарь |
| `build-linux/simulation/fuzz_harness_standalone` | ✅ Replay с GraphLogger |
| Phase 2: real pool.cpp fuzzer | 🔲 Будущая работа |

---

## Два уровня фаззинга

### Phase 1 (реализована): протокольный уровень

`fuzz_harness.cpp` фаззит **модель протокола** (ConsensusHarness-логику).
Находит баги в **дизайне протокола** — комбинации Byzantine поведений
которые нарушают safety/liveness.

### Phase 2 (будущее): уровень реализации

Фаззинг реального `pool.cpp` через mock actor runtime.
Находит баги в **реализации** — TL-десериализация, integer overflow, use-after-free.
Требует ~500 строк scaffolding (MockBus, MockKeyring, MockDb).

---

## Стратегии мутации: снаружи внутрь

Классический подход: случайные байты → структурная валидность → семантика.
Каждый слой сужает пространство поиска для следующего.

```
Пространство: ~256^N (все байт-последовательности)
      │
      ▼  [FuzzedDataProvider]        ← СЛЕДУЮЩИЙ ШАГ
      │  Структурная валидность: только осмысленные комбинации
      │  n_validators ∈ [3,6], action ∈ {0..4}
      │  Сужение: ~10^6×
      │
      ▼  [Dictionary]
      │  Граничные значения: slot=0, slot=MAX, N=threshold-1
      │  Приоритизирует corner cases
      │
      ▼  [Corpus из testnet]
      │  Реальные паттерны из trace.ndjson вместо синтетики
      │  ~50 файлов вместо 4 seed
      │
      ▼  [AFL++ grammar mutation]
      │  Мутирует на уровне "слот/сессия", не байт
      │  Не ломает структуру при мутации
      │
      ▼
  Интересные inputs → Neo4j → Cypher → аномалии
```

### FuzzedDataProvider (рекомендуется первым)

Заменяет самодельный `FuzzReader` — libFuzzer видит структуру и мутирует осмысленно:

```cpp
#include <fuzzer/FuzzedDataProvider.h>

FuzzedDataProvider fdp(data, size);
int n_validators = fdp.ConsumeIntegralInRange(3, 6);
int n_slots      = fdp.ConsumeIntegralInRange(1, 15);
for (int v = 0; v < n_validators; v++) {
    auto action = fdp.ConsumeEnum<ValidatorAction>();
}
```

### Dictionary

```
# simulation/fuzz.dict
"\x00"   # slot=0
"\xff"   # slot=255 (overflow)
"\x03"   # N=threshold (граница кворума)
"\x02"   # DoubleNotarize
"\x03"   # NotarizeAndSkip
```
```bash
./fuzz_harness corpus/ -dict=simulation/fuzz.dict
```

### Corpus из testnet

`trace.ndjson` → `simulation/scripts/trace_to_corpus.py` → corpus-файлы.
Фаззер мутирует реальные паттерны событий вместо синтетики.

### AFL++ с grammar mutation

```
session := n_validators n_slots slot*
slot    := validator_action{n_validators}
validator_action := HONEST | DROP | DOUBLE | NOTARIZE_SKIP | ABSTAIN
```

---

## Стратегии мутации: изнутри наружу (model-guided)

**Ключевая идея:** у нас есть граф аномалий в Neo4j — это и есть спецификация
того что должно быть нарушено. Вместо случайного поиска — генерируем входы
которые **целенаправленно давят** на известные уязвимости.

Три уровня реализации:

### A. Targeted seed generation (Python, ~2 часа)

Каждый Cypher-запрос из `CYPHER_QUERIES.md` → генератор corpus-файлов
которые максимизируют шанс нарушить соответствующее свойство:

| Аномалия | Стратегия генерации |
|---|---|
| `#dual-cert` | Byzantine лидер + split групп ≥ threshold каждая |
| `#equivocation` | DoubleNotarize + разные delivery группы |
| `#amnesia-gap` | VoteIntentSet без Persisted (краш в нужный момент) |
| `#alarm-skip-after-notarize` | AlarmSkip когда votedNotar=true |
| `#notarize-skip-split` | NotarizeAndSkip у нескольких валидаторов |

```python
# simulation/scripts/gen_targeted_corpus.py

def gen_dual_cert_pressure(n=4, threshold=3):
    """Byzantine лидер шлёт разным группам разные candidateId.
    Каждая группа >= threshold → два кандидата набирают кворум."""
    for leader in range(n):
        for split in all_splits(n, threshold):
            yield encode(leader=leader, group_a=split.a, group_b=split.b)
```

Corpus из этих файлов → libFuzzer оказывается **сразу в опасной зоне**
и мутирует вокруг неё, а не ищет её с нуля.

### B. Properties as in-process assertions (~полдня)

Перенести все Cypher-проверки из Neo4j в C++ прямо в harness.
Каждая аномалия становится **оракулом** — libFuzzer напрямую ищет входы
которые её вызывают, без round-trip через relay.mjs и Neo4j:

```cpp
// Вместо: relay → Neo4j → Cypher → результат
// Прямо в LLVMFuzzerTestOneInput:

// #dual-cert (SAFETY — crash):
if (finalize_certs[slot].size() > 1) __builtin_trap();

// #equivocation (log):
for (auto& [v, votes] : notarize_votes[slot])
    if (votes.size() > 1) log_anomaly("equivocation", slot, v);

// #amnesia-gap (log):
if (vote_intent_set[slot] && !vote_intent_persisted[slot])
    log_anomaly("amnesia-gap", slot, 0);

// #notarize-skip-split (log — известный незадетектированный баг):
if (did_notarize[v] && did_skip[v])
    log_anomaly("notarize-skip-split", slot, v);
```

Скорость: **240K итераций/сек без Neo4j** vs ~100 итераций/сек с Neo4j round-trip.

### C. Coverage-directed к аномалиям (directed fuzzing, ~неделя)

Самый умный вариант: **обратная связь от графа к фаззеру**.

Вместо покрытия кода — минимизировать «расстояние до нарушения инварианта».
Реализуется через `LLVMFuzzerCustomMutator`:

```
libFuzzer генерирует сценарий
    → harness запускает симуляцию
    → вычисляет "расстояние" до нарушения свойства
      (например: max(notarize_weight) - threshold для #dual-cert)
    → возвращает сигнал мутатору
    → мутатор делает шаг в сторону уменьшения расстояния
```

Это **не случайный поиск** — это градиентный спуск в пространстве протокольных решений.

---

## Стратегии мутации: обратная достижимость (backwards reachability)

**Ключевая идея:** уязвимость — это конечная точка каскада состояний. Вместо поиска
вперёд (случайные входы → надеемся попасть) идём **назад от нарушения**,
вычисляя предусловия на каждом шаге (wp-исчисление Дейкстры).

```
VIOLATION: finalize_certs[slot].size() > 1
  ← Pre-1: два кандидата набрали finalize_weight >= threshold
    ← Pre-2: два кандидата набрали notarize_weight >= threshold
      ← Pre-3: Byzantine валидатор голосует за оба +
               две группы ≥ threshold получили разные candidateId
        ← Input: {SplitPropose лидер, partition(validators, A≥thr, B≥thr)}
```

Каждый шаг назад даёт **более широкое, но уже ограниченное** пространство.
Нереалистичные входы отпадают сами — они не лежат ни в одном Pre(k).

### Применение к протоколу (Phase 1)

На уровне модели (N=3..6, threshold=N-1) пространство **аналитически конечно**.
Для `#dual-cert` при N=4: `C(4,3) = 4` разбиения — это весь targeted corpus.
`gen_targeted_corpus.py` решает систему неравенств явно:

```python
# ∃ partition(validators) : |A| >= threshold AND |B| >= threshold
# AND leader sends cand_0 to A, cand_1 to B
for N in range(3, 7):
    threshold = N - 1
    for split in combinations_with_threshold(N, threshold):
        emit_corpus_file(N, split)
```

Никакого случайного поиска — **полное покрытие опасной зоны** для каждой уязвимости.

### Phase 2: векторные эмбеддинги состояний

Для реального `pool.cpp` аналитическое вычисление Pre(k) нереально (пространство ~2^64).
Здесь применим **vector-guided fuzzing**:

```
snapshot C++ состояния (notarize_weight map, requests_ queue, voted_notar flags)
    → кодируем в числовой вектор
    → Faiss/hnswlib хранит "эталонные опасные состояния" из известных PoC
    → при фаззинге: cosine similarity к ближайшему опасному состоянию
    → это фидбэк мутатору (вместо code coverage)
```

Мутатор делает шаг в сторону **уменьшения расстояния до нарушения**,
не в сторону случайного покрытия новых базовых блоков.

---

## Комбинированная стратегия: оптимальный порядок

```
Шаг 1: FuzzedDataProvider           → структурная валидность
        +
        gen_targeted_corpus.py       → стартуем в опасной зоне
        ↓
        Corpus прогрет и структурирован

Шаг 2: Properties as assertions      → убираем Neo4j из inner loop
        +
        Dictionary                   → граничные значения
        ↓
        240K iter/sec, прямые crashes

Шаг 3: (если crashes не найдены за 24ч)
        Corpus из testnet             → реальные паттерны
        +
        AFL++ grammar                 → мутации на уровне протокола

Шаг 4: (для найденных crashes)
        Replay с GraphLogger          → trace.ndjson
        relay.mjs → Neo4j             → Cypher-запросы
        → понять что именно нарушено и почему
```

**Шаги 1+2** дают 80% выхлопа за 20% усилий.
**Шаги 3+4** нужны если 1+2 за 24 часа не нашли `SAFETY VIOLATION`.

---

## Workflow при находке краша

```bash
# 1. libFuzzer сохранил crash:
#    simulation/crashes/crash-<hash>

# 2. Replay с трассой:
GRAPH_LOGGING_ENABLED=1 \
GRAPH_LOG_FILE=$(pwd)/simulation/trace.ndjson \
  ./build-linux/simulation/fuzz_harness_standalone \
  simulation/crashes/crash-<hash>

# 3. Отправить в Neo4j:
cd simulation && node relay.mjs --clear trace.ndjson

# 4. Запросить аномалии:
node query.mjs <sessionId>
```

---

## Регламент прогонов

Corpus **накапливается** — не чистить без причины:

```bash
mkdir -p simulation/corpus_fuzz_run simulation/crashes

# Каждый прогон (первый и все последующие):
./build-fuzz/simulation/fuzz_harness \
  simulation/corpus_fuzz_run/ \
  simulation/corpus_fuzz/ \
  -max_total_time=3600 \
  -artifact_prefix=simulation/crashes/
```

Чистить corpus только если изменился код harness (например, изменился enum `ValidatorAction`).
После изменения harness — перегенерировать seed corpus: `python3 simulation/scripts/gen_targeted_corpus.py`
Минимизация: `./fuzz_harness -merge=1 corpus_min/ corpus_fuzz_run/`

---

## Что реализовано в Phase 1 ([5aa6dab6](https://github.com/a1oleg/tonGraph/commit/5aa6dab6))

### ValidatorAction (6 действий)

| Action | Значение | Что делает |
|---|---|---|
| `Honest` | 0 | Голосует за полученный кандидат честно |
| `DropReceive` | 1 | Не получает кандидат → SkipVote |
| `DoubleNotarize` | 2 | Голосует за полученный + `cand_equiv` (equivocation) |
| `NotarizeAndSkip` | 3 | Notarize + Skip в одном слоте (известный баг) |
| `NoVote` | 4 | Воздерживается (тест liveness) |
| `SplitPropose` | 5 | [лидер] шлёт `cand_main` группе A, `cand_split` группе B |

### Инварианты в harness (в-процессные оракулы)

| Проверка | Тип | Триггер |
|---|---|---|
| Dual FinalizeCert | SAFETY — `__builtin_trap()` | `finalize_certs[slot].size() > 1` |
| Equivocation | INVARIANT — stderr | Один валидатор → два разных notarize cand |
| Notarize+Skip | INVARIANT — stderr | Один валидатор → notarize и skip в одном слоте |

### gen_targeted_corpus.py — 272 файла

| Генератор | Файлов | Покрытие |
|---|---|---|
| `gen_dual_cert_pressure` | 130 | Все разбиения с хотя бы одной группой ≥ threshold−1 |
| `gen_equivocation_pressure` | 88 | DoubleNotarize на каждой позиции + пары Byzantine |
| `gen_notarize_skip_pressure` | 18 | NotarizeAndSkip на каждой позиции |
| `gen_liveness_pressure` | 36 | Leader drop + threshold−1 no-vote |

---

## Следующие шаги (приоритет)

1. ~~**`FuzzedDataProvider`**~~ — ✅ [54933808](https://github.com/a1oleg/tonGraph/commit/54933808) реализовано
2. **Properties as assertions** — уже частично: equivocation и notarize+skip детектируются; добавить остальные Cypher-проверки
3. **Phase 2** — real `pool.cpp` fuzzer (MockBus + MockKeyring + MockDb)
