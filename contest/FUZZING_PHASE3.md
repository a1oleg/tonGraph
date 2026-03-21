# Фаззинг — Phase 3: направленный поиск нарушений безопасности

[← Phase 2](FUZZING_PHASE2.md) | [Общий план](FUZZING_PLAN.md) | [→ Phase 4](FUZZING_PHASE4.md)


## Текущий прогресс

```
Шаг 1  ✅  state-vector counters + value-profile → cov: 797, ft: 1999, corpus: 480, крашей: 0
Шаг 2  ✅  Consensus актор + stub-резолверы → cov: 834 (+37), ft: 2833 (+834), крашей: 0
Шаг 3  ✅  VectorDB cosine similarity + post-crash messages → cov: 849 (+15), ft: 2925, крашей: 0
Шаг 4  ✅  Пробный запуск на одной машине — cov: 854, ft: 3162, крашей: 0 (запущен и остановлен 2026-03-19)
```

---

## Шаг 1 — state-vector counters + value-profile ✅

**Что реализовано в `fuzz_pool.cpp`:**
- `g_state_counters[136]` — per-slot (16 слотов × 8 событий) + 8 глобальных байт
- `SlotEvent`: `SE_NOTAR_VOTE`, `SE_SKIP_VOTE`, `SE_FINAL_VOTE`, `SE_NOTAR_CERT`,
  `SE_BOTH_NS` (danger), `SE_CERT_SKIP` (danger), `SE_POST_CRASH`
- `slot_event()` эмитирует `__sanitizer_cov_trace_cmp1(counter, 0)` пары — без PC-table mismatch
- Запуск: добавить `-use_value_profile=1` к аргументам fuzzer

**Результат:** `ft` (feature targets) ~1050 → **1950** (+900 семантических путей) с `-use_value_profile=1`,
без изменений production-кода.

**Ограничение:** сигнал бинарный («эта пара встречалась / нет»), не непрерывный.
Полный gradient descent к опасным состояниям — Шаг 3 (VectorDB).

### Результаты продолжённого прогона (2026-03-19)

Прогон продолжился после Phase 2 на том же corpus (без `-use_value_profile=1`),
16 воркеров, остановлен вручную:

| Параметр | Значение |
|---|---|
| Скорость | ~2650 iter/sec на воркер |
| Coverage | `cov: 797` (+2 от Phase 2) |
| ft (без value_profile) | `ft: 1999` |
| Corpus | 480 файлов (все воркеры) |
| **Крашей** | **0** |

**Вывод:** coverage и ft на плато. Corpus богатый (480 файлов).
Переходим к Шагу 2 (Consensus актор).

---

## Шаг 2 — Consensus актор + stub-резолверы 🔲

### Зачем

`alarm-skip-after-notarize` — баг когда после crash+recover Pool выдаёт SkipVote
для слота где уже был NotarizeVote. Требует `Consensus` актора (consensus.cpp),
которого нет в текущем fuzz_pool harness.

Сценарий:
1. Validator голосует `NotarizeVote` для слота X → db пишет `ourVote`
2. Crash (`n_lose=1` — теряем `ourVote`)
3. На restart: `first_nonannounced_window > 0` → ConsensusImpl публикует `SkipVote{X}`
4. Pool накапливает SkipVotes → SkipCert для слота X
5. `g_notar_by_slot[X]` уже заполнен → `__builtin_trap()` ✓

### Что нужно добавить в fuzz_pool.cpp

```cpp
// 1. Добавить к configure_and_start_bus():
Consensus::register_in(*S.runtime);

// 2. FuzzStateResolver — отвечает на ResolveState немедленной ошибкой
//    (start_generation() зависает только на это; с ошибкой — gracefully abort)
class FuzzStateResolver final : public SpawnsWith<FuzzBus>, ConnectsTo<FuzzBus> {
  template <>
  td::actor::Task<ResolveState::Result> process(FuzzBusHandle, std::shared_ptr<ResolveState>) {
    co_return td::Status::Error("mock");
  }
  // + StopRequested handler
};

// 3. FuzzCandidateResolver — аналогично для ResolveCandidate
```

### Сложность

`ResolveState::Result` содержит `ChainStateRef state` — сложный тип.
Для stub достаточно вернуть ошибку: `start_generation()` в consensus.cpp
запущен через `.start().detach()`, ошибка не проваливается наружу.

### Что делать: план на 1–2 дня

**День 1 — реализация:**

1. Изучить интерфейс `ResolveState` и `ResolveCandidate` в `consensus.cpp` —
   понять какие именно типы возвращаются, убедиться что `co_return Error` не роняет bus
2. Написать `FuzzStateResolver` и `FuzzCandidateResolver` по скетчу выше
3. Добавить `Consensus::register_in(*S.runtime)` в `configure_and_start_bus()`
4. Собрать — ожидаем compile errors вокруг `ChainStateRef`, чинить до зелёного
5. Проверить что harness вообще запускается: один ручной тест-input, нет segfault/hang

**День 2 — тестовый прогон и верификация:**

```bash
REPO=$(pwd)
mkdir -p simulation/corpus_fuzz_pool2 simulation/crashes_pool2
tmux new-session -d -s fuzz_consensus \
  "cd $REPO && timeout 3600 ./build-fuzz2/test/consensus/fuzz_pool \
   $REPO/simulation/corpus_fuzz_pool/ \
   $REPO/simulation/corpus_fuzz_pool2/ \
   -max_total_time=3600 -jobs=$(nproc) \
   -use_value_profile=1 \
   -artifact_prefix=$REPO/simulation/crashes_pool2/ \
   >> $REPO/simulation/fuzz_consensus.log 2>&1"
```

**Что ищем в результатах:**

| Сигнал | Интерпретация |
|---|---|
| `crashes_pool2/` не пустой | alarm-skip-after-notarize сработал → воспроизводим вручную |
| `cov:` заметно вырос (>797) | ConsensusImpl добавил новые пути — alarm() достигнут |
| `cov:` не изменился | Consensus актор не активируется — смотреть почему (drain rounds мало?) |
| `ft:` растёт дольше чем за 5 мин | Хорошо — новое пространство состояний исследуется |

**На что смотреть в Cypher после краша:**
```cypher
-- Проверить alarm-skip-after-notarize:
MATCH (a:AlarmSkip)
WHERE a.votedNotar = true
RETURN a.slot, a.tsMs
```
→ [CYPHER_QUERIES.md#alarm-skip-after-notarize](CYPHER_QUERIES.md#alarm-skip-after-notarize)

### Результаты (2026-03-19)

| Параметр | Значение |
|---|---|
| Скорость | ~2180 iter/sec на воркер |
| Coverage | `cov: 834` (+37 от Шага 1 — новые пути ConsensusImpl) |
| ft (с `-use_value_profile=1`) | `ft: 2833` (+834 от Шага 1) |
| **Крашей** | **0** |

**Вывод:** ConsensusImpl добавил 37 новых кодовых путей (alarm(), start_up() SkipVote
broadcast, LeaderWindowObserved handler). Сценарий alarm-skip-after-notarize не сработал
автоматически — требует точной последовательности (NotarVote → crash → restart с
`first_nonannounced_window > 0` → SkipVote → quorum SkipVotes от других валидаторов).
Случайный мутатор не находит её за разумное время → нужен VectorDB guidance (Шаг 3).

---

## Шаг 3 — Vector similarity guidance ✅

### Концепция

Шаг 1 даёт бинарный сигнал «эта пара состояний встречалась». Шаг 3 добавляет
**непрерывный** сигнал направленности: насколько текущее состояние близко к
конкретному опасному сценарию.

**Что выступает «базой»:** не отдельная VectorDB (Faiss/hnswlib не нужна при
3 reference vectors). База — три константных float-массива в `.bss` процесса.
Similarity search — brute-force O(3 × 16) per iteration. Faiss/hnswlib актуален
когда reference vectors > ~100 или они динамические (из Neo4j/simulation).

**Три компонента:**

1. **Reference vectors** (3 штуки, hardcoded) — паттерн опасного состояния
   per-slot (размерность 8 = SE_STRIDE):
   - `REF_ALARM_SKIP`: `SE_NOTAR_VOTE` + `SE_NOTAR_CERT` + `SE_POST_CRASH` + `SE_SKIP_VOTE`
   - `REF_AMNESIA`: `SE_NOTAR_VOTE` + `SE_NOTAR_CERT` + `SE_POST_CRASH`
   - `REF_DUAL_CERT`: `SE_NOTAR_CERT` + `SE_CERT_SKIP`

2. **Snapshot** — `g_state_counters[slot * 8 + event]` (уже пишется в Шаге 1),
   передаётся в `cosine_sim_slot()` после каждого `LLVMFuzzerTestOneInput`.

3. **Similarity → libFuzzer signal**: `__sanitizer_cov_trace_cmp1(channel, sim_byte)`,
   48 уникальных каналов (3 ref × 16 slots). С `-use_value_profile=1` libFuzzer
   gradient descent-ит к более высокому sim_byte без LLVMFuzzerCustomMutator.

### Отличие от value-profile (Шаг 1)

| | Шаг 1 (value-profile) | Шаг 3 (vector similarity) |
|---|---|---|
| Сигнал | бинарные пары (arg1, arg2) | continuous cosine similarity [0,1] |
| Направление | хаотичное — "новые комбинации" | целевое — "ближе к конкретному опасному состоянию" |
| "База" | нет | 3 float-массива в памяти (brute-force) |
| Faiss/hnswlib | не нужен | нужен если reference vectors > ~100 |
| Сложность | ✅ реализован | ✅ реализован |

### Реализация (2026-03-19)

Вместо Faiss/hnswlib реализован brute-force cosine similarity — достаточно для 3 reference vectors:

- **`REF_ALARM_SKIP`**: `SE_NOTAR_VOTE` + `SE_NOTAR_CERT` + `SE_POST_CRASH` + `SE_SKIP_VOTE`
- **`REF_AMNESIA`**: `SE_NOTAR_VOTE` + `SE_NOTAR_CERT` + `SE_POST_CRASH`
- **`REF_DUAL_CERT`**: `SE_NOTAR_CERT` + `SE_CERT_SKIP`

Per-slot: `cosine_sim_slot(ref, &g_state_counters[slot * SE_STRIDE])` → `sim_byte ∈ [0,255]`
Emit: `__sanitizer_cov_trace_cmp1(0xA0 + r*0x10 + slot, sim_byte)` — 48 уникальных каналов.

**Также добавлено:** `n_post` сообщения после краша (`uint8, 0..7`) — критично для alarm-skip:
ConsensusImpl после рестарта отправляет SkipVote{X}, но quorum (3 из 4) требует ещё 2 голоса.
Без post-crash injection quorum никогда не достигался.

### Результаты (2026-03-19)

| Параметр | Значение |
|---|---|
| Скорость | ~2800–3160 iter/sec на воркер |
| Coverage | `cov: 849` (+15 от Шага 2) |
| ft (с `-use_value_profile=1`) | `ft: 2925` |
| Corpus | 966 файлов |
| **Крашей** | **0** |

**Вывод:** cosine similarity guidance расширяет семантическое пространство,
coverage плато стабильное. alarm-skip последовательность потенциально достижима
(post-crash injection добавлен), но требует точной мутации на конкретный слот →
направленный corpus нужен для форсирования.

### Связь с FUZZING_DISTRIBUTED.md

[Уровень 4](FUZZING_DISTRIBUTED.md#уровень-4--distance-guided-с-общей-vector-db)
описывает распределённую версию: Faiss/hnswlib на отдельной машине,
воркеры шлют снапшоты и получают similarity score.

Для одной машины: Faiss работает локально в той же памяти процесса,
snapshot передаётся напрямую без сети.

### Reference vectors — откуда брать

**1. Теоретический анализ** (вручную, без запуска):

| Инвариант | Опасное состояние (reference vector) |
|---|---|
| alarm-skip | `voted_notar[X]=1` + `skip_weight[X]` ≥ quorum−1 |
| amnesia-gap | `voted_notar[X]=1` (pre-crash) + `voted_notar[X]=0` (post-crash) |
| dual-cert | `notarize_cert[X]` + `skip_cert[X]` одновременно |

**2. Из GraphLogger + Neo4j** (near-miss из реальных прогонов):

```bash
# 1. Запустить simulation с GraphLogger включённым:
./build/test/consensus/test-consensus --graph-log simulation/graph.json

# 2. Загрузить в Neo4j (см. GRAPH_LOGGING.md)

# 3. Найти near-miss моменты — слоты где skip_weight почти достиг порога
#    при уже выданном notarize:
MATCH (v:Validator)-[n:notarize]->(c:Candidate)
MATCH (v)-[sk:skip]->(se:SkipEvent)
WHERE n.slot = sk.slot
RETURN v.sessionId AS session, v.validatorIdx AS validator, n.slot AS slot
# → каждая строка = near-miss момент для alarm-skip

# 4. Snapshotить g_state_counters в этот момент → reference vector
```

Запросы для остальных инвариантов: [CYPHER_QUERIES.md](CYPHER_QUERIES.md).

### Snapshot extraction

Состояние PoolImpl недоступно снаружи напрямую. Варианты:
- Добавить debug-метод в PoolImpl (производственный код не меняется в prod-сборке,
  только под `#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION`)
- Реконструировать из events (`OutgoingProtocolMessage` + cert events) —
  это то, что уже делает Шаг 1 через `g_state_counters`


