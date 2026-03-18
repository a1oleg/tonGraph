# Фаззинг simplex pool — план

## Вывод: возможно, но нетривиально

`pool.cpp` — самостоятельная консенсусная логика, но глубоко вшита в `td::actor` runtime.
Для изолированного harness нужно поднять мини-runtime с mock-компонентами.

---

## Что такое pool.cpp

`PoolImpl` — сердце simplex консенсуса. Он:
- Принимает входящие голоса (`IncomingProtocolMessage`) от других валидаторов
- Накапливает нотаризационные и финализационные веса по слотам
- Выдаёт сертификаты (`NotarizeCert`, `FinalizeCert`) когда набирается кворум
- Детектирует Byzantine поведение через `check_invariants()`

Все взаимодействия — через `Bus` (pub/sub события в `td::actor::Runtime`).

---

## Граф зависимостей

```
LLVMFuzzerTestOneInput(data, size)
  │
  └─ td::actor::Runtime          ← нужен (но легковесный, ~50 строк setup)
       │
       └─ Bus (mock)             ← создаём сами
            ├─ validator_set     ← тестовые ключи (Ed25519, генерим один раз)
            ├─ local_id          ← один из validator_set
            ├─ Keyring (mock)    ← подписывает фиксированным ключом
            ├─ Db (mock)         ← in-memory map, ~30 строк
            └─ CollatorSchedule  ← тривиальный интерфейс
```

---

## Компоненты: что мокать, что реально использовать

| Компонент | Сложность мока | Комментарий |
|---|---|---|
| `td::actor::Runtime` | Низкая | Уже используется в ConsensusHarness |
| `Bus` структура | Низкая | Просто struct, заполняем поля |
| `Db` интерфейс | Низкая | `std::map<string, string>` в памяти |
| `CollatorSchedule` | Минимальная | Возвращает фиксированного коллатора |
| `Keyring` актор | Средняя | Нужен реальный Ed25519 mock-актор |
| `validator_set` | Низкая | Генерим 3 тестовых keypair заранее |
| Проверка подписей | Средняя | Можно отключить флагом в тестовых ключах |

**Блокеров нет** — `ConsensusHarness.cpp` уже поднимает полный simplex runtime
с 3–5 акторами. Фаззинг-harness — это тот же harness, но без сценария,
с инжекцией произвольных байт вместо честных сообщений.

---

## Что фаззить: точки входа

### 1. `IncomingProtocolMessage` — основная точка (рекомендуется первой)

Pool принимает TL-сериализованные сообщения от пиров:

```cpp
// bus.h
struct IncomingProtocolMessage {
  td::BufferSlice data;     // ← сюда подаём data от фаззера
  PeerValidatorId source;
};
```

Фаззер подаёт произвольные байты как `data`. Мы также мутируем `source`
(чтобы покрыть пути «сообщение от лидера» vs «от обычного валидатора»).

**Что ищем:**
- Краш в TL-десериализаторе (`td::TlParser`)
- Integer overflow в `slot` или `weight`
- Нарушение инварианта `voted_notar && voted_skip` → `InvariantViolation` событие
- Бесконечный цикл при обработке

### 2. `BroadcastVote` — голос от нашего валидатора

```cpp
struct BroadcastVote {
  Vote vote;   // NotarizeVote | FinalizeVote | SkipVote
};
```

Фаззер генерирует синтетические голоса с мутированными `slot`, `candidateId`, `weight`.

**Что ищем:**
- Двойная нотаризация в одном слоте (equivocation без детекции)
- `voted_notar + voted_skip` в одном слоте (дыра в `check_invariants`)

### 3. Bootstrap replay — краш при восстановлении

При старте Pool читает из DB сохранённые голоса и воспроизводит их.
Фаззер заполняет mock-DB мусорными данными до старта Pool.

**Что ищем:**
- Краш при malformed DB-данных
- Конфликт при replay → `ConflictTolerated` без `InvariantViolation`

---

## Corpus

Не начинаем с нуля — берём реальные форматы из `simulation/trace.ndjson`:

```bash
# Извлечь candidateId и sessionId для построения реальных TL-структур
grep '"event":"VoteCast"' simulation/trace.ndjson | head -20
```

Дополнительно — corpus из существующих unit-тестов TON:
```bash
find . -name "*test*consensus*" -o -name "*consensus*test*" | grep -v build
```

Стартовый corpus (~10 файлов) → libFuzzer мутирует автоматически.

---

## Интеграция с GraphLogger

Фаззер + Neo4j — **две независимые системы**, которые работают последовательно:

```
Фаза 1: libFuzzer (быстро, миллионы итераций)
  └─ ищет crash / assertion / новые coverage-пути
  └─ сохраняет интересные inputs в corpus/

Фаза 2: Replay интересных inputs через ConsensusHarness (медленно)
  └─ GRAPH_LOGGING_ENABLED=1
  └─ relay.mjs → Neo4j
  └─ Cypher-запросы из CYPHER_QUERIES.md
```

Фаззер — **генератор сценариев**, Neo4j — **анализатор что они означают**.

---

## Структура файлов

```
simulation/
  fuzz_pool.cpp          ← LLVMFuzzerTestOneInput + harness
  fuzz_helpers.h         ← MockBus, MockKeyring, MockDb (~150 строк)
  corpus/
    vote_notarize.bin    ← реальный NotarizeVote из трассы
    vote_finalize.bin    ← реальный FinalizeVote
    vote_skip.bin        ← реальный SkipVote
    cert_notarize.bin    ← реальный NotarizeCert
  CMakeLists.txt         ← добавить таргет fuzz_pool
```

---

## CMake-таргет

```cmake
# simulation/CMakeLists.txt — добавить:
if (DEFINED ENV{FUZZING})
  add_executable(fuzz_pool fuzz_pool.cpp fuzz_helpers.cpp)
  target_compile_options(fuzz_pool PRIVATE -fsanitize=fuzzer,address -g)
  target_link_options(fuzz_pool PRIVATE -fsanitize=fuzzer,address)
  target_link_libraries(fuzz_pool
    validator tdactor tdutils keyring
    simulation  # GraphLogger
  )
endif()
```

Запуск:
```bash
FUZZING=1 cmake -B build-fuzz -DCMAKE_C_COMPILER=clang-18 -DCMAKE_CXX_COMPILER=clang++-18 -G Ninja
cmake --build build-fuzz --target fuzz_pool

./build-fuzz/simulation/fuzz_pool simulation/corpus/ \
  -max_total_time=3600 \
  -jobs=4 \
  -artifact_prefix=simulation/crashes/
```

---

## Оценка объёма работы

| Шаг | Файл | Строк | Сложность |
|---|---|---|---|
| MockBus + MockDb + MockKeyring | `fuzz_helpers.h/.cpp` | ~200 | Средняя |
| LLVMFuzzerTestOneInput | `fuzz_pool.cpp` | ~100 | Низкая |
| Corpus из трассы | скрипт Python | ~50 | Низкая |
| CMakeLists.txt | добавить секцию | ~15 | Низкая |
| **Итого** | | **~365** | |

ConsensusHarness уже решил 80% проблем с мокингом actor runtime —
переиспользуем его scaffolding, заменяем сценарий на фаззер-инжекцию.

---

## Следующий шаг

1. Посмотреть как `ConsensusHarness.cpp` поднимает Bus — взять как основу для MockBus
2. Написать `fuzz_helpers.h` с MockKeyring (Ed25519 через `crypto/elliptic-curve.h`)
3. Написать `fuzz_pool.cpp` — сначала только `IncomingProtocolMessage` точка входа
4. Построить corpus из `simulation/trace.ndjson`

---

## Умный фаззинг: варианты стратегий

Случайный перебор байт — наихудшая стратегия. Варианты от простого к сложному:

### 1. Dictionary (15 мин, низкий выхлоп)

libFuzzer автоматически накапливает словарь (мы видели после 30 сек: `"skip:"`, `"certTy"`, `"\x01\x00"`).
Добавить явный словарь значимых значений:

```
# simulation/fuzz.dict
"\x00"   # slot=0 (corner case)
"\xff"   # slot=255 (overflow)
"\x03"   # N=3 (минимум валидаторов)
"\x06"   # N=6 (максимум)
"\x02"   # DoubleNotarize
"\x03"   # NotarizeAndSkip
```

```bash
./build-fuzz/simulation/fuzz_harness ... -dict=simulation/fuzz.dict
```

### 2. FuzzedDataProvider — рекомендуется первым (1–2 часа, высокий выхлоп)

Вместо ручной интерпретации байт использовать `FuzzedDataProvider` из clang.
Он **осмысленно распределяет энтропию** — мутирует `n_validators` не ломая остальные поля:

```cpp
#include <fuzzer/FuzzedDataProvider.h>

FuzzedDataProvider fdp(data, size);
int n_validators = fdp.ConsumeIntegralInRange(3, 6);
int n_slots      = fdp.ConsumeIntegralInRange(1, 15);
for (int v = 0; v < n_validators; v++) {
    auto action = fdp.ConsumeEnum<ValidatorAction>();
}
```

Принципиально меняет качество мутаций — libFuzzer видит структуру входа.
Требует замены `FuzzReader` в `fuzz_harness.cpp` на `FuzzedDataProvider`.

### 3. Corpus из реального testnet трафика (2–3 часа, средний выхлоп)

`simulation/trace.ndjson` содержит реальные последовательности событий от живых валидаторов.
Конвертировать в corpus-файлы — фаззер будет мутировать **реальные паттерны**:

```
CandidateReceived → Honest
VoteCast notarize → Honest
VoteCast skip     → DropReceive
```

Скрипт: `simulation/scripts/trace_to_corpus.py`

### 4. AFL++ с grammar mutation (день, высокий выхлоп)

AFL++ умеет мутировать по грамматике протокола:

```
session := n_validators n_slots slot*
slot    := validator_action{n_validators}
validator_action := HONEST | DROP | DOUBLE | NOTARIZE_SKIP | ABSTAIN
```

Мутирует на уровне грамматики, а не байт — находит corner cases
которые coverage-guided мутации байт пропускают.

### Регламент повторных прогонов

Corpus **накапливается** между прогонами — не чистить без причины:

```bash
# Первый прогон:
mkdir -p simulation/corpus_fuzz_run simulation/crashes
./build-fuzz/simulation/fuzz_harness \
  simulation/corpus_fuzz_run/ \
  simulation/corpus_fuzz/ \
  -max_total_time=3600 \
  -artifact_prefix=simulation/crashes/

# Все последующие — то же самое, corpus_fuzz_run/ растёт:
./build-fuzz/simulation/fuzz_harness \
  simulation/corpus_fuzz_run/ \
  simulation/corpus_fuzz/ \
  -max_total_time=3600 \
  -artifact_prefix=simulation/crashes/
```

Чистить corpus только если изменился код harness (новые ветки делают старый corpus нерелевантным)
или для минимизации: `./fuzz_harness -merge=1 corpus_min/ corpus_fuzz_run/`.
