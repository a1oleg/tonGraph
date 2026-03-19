# Фаззинг — Phase 3: направленный поиск нарушений безопасности

[← Phase 2](FUZZING_PHASE2.md) | [Общий план](FUZZING_PLAN.md) | [Распределённый фаззинг](FUZZING_DISTRIBUTED.md)


## Текущий прогресс

```
Шаг 1  ✅  state-vector counters + value-profile → cov: 797, ft: 1999, corpus: 480, крашей: 0
Шаг 2  🔲  Consensus актор + stub-резолверы (alarm-skip-after-notarize)
Шаг 3  🔲  VectorDB guidance (Faiss/hnswlib)
Шаг 4  🔲  Распределённый запуск (corpus sync + стратегии)
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

**Оценка:** 1–2 дня.

---

## Шаг 3 — VectorDB guidance 🔲

### Концепция

Шаг 1 реализует value-profile пары (`__sanitizer_cov_trace_cmp1`) —
бинарный сигнал «эта комбинация состояний встречалась». Полная vector guidance:

1. **Эталонные опасные состояния** (`reference_vectors`) — снимки состояния
   pool.cpp перед известными SAFETY VIOLATION (из теоретического анализа протокола
   или из PoC тестов).

2. **Snapshot текущего состояния** после каждого `LLVMFuzzerTestOneInput`:
   - для каждого слота: `notarize_weight`, `skip_weight`, `voted_notar`, certs
   - flattened в float-вектор размерности ~64

3. **Cosine similarity** к ближайшему reference_vector → fitness score

4. **Мутатор** (`LLVMFuzzerCustomMutator`) предпочитает мутации,
   которые увеличивают fitness score.

### Отличие от value-profile (Шаг 1)

| | Шаг 1 (value-profile) | Шаг 3 (VectorDB) |
|---|---|---|
| Сигнал | бинарные пары (arg1, arg2) | continuous cosine similarity [0,1] |
| Направление | хаотичное — "новые комбинации" | целевое — "ближе к конкретному опасному состоянию" |
| Зависимость | нет | Faiss/hnswlib |
| Сложность | ✅ реализован | ~1 неделя |

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

**Оценка:** 1 неделя.

---

## Шаг 4 — Распределённый запуск 🔲

При наличии нескольких машин Phase 3 масштабируется горизонтально.

### Быстрый старт: corpus sync (Уровень 1)

→ Описание в [FUZZING_DISTRIBUTED.md — Уровень 1](FUZZING_DISTRIBUTED.md#уровень-1--corpus-sync-просто-без-координации)

```bash
# Каждый час на каждой машине:
rsync -a machine2:~/tonGraph/simulation/corpus_fuzz_pool/ simulation/corpus_fuzz_pool/
./build-fuzz2/test/consensus/fuzz_pool -merge=1 corpus_merged/ simulation/corpus_fuzz_pool/
mv corpus_merged/* simulation/corpus_fuzz_pool/
```

### Специализация по стратегиям (Уровень 2)

→ Описание в [FUZZING_DISTRIBUTED.md — Уровень 2](FUZZING_DISTRIBUTED.md#уровень-2--разделение-по-стратегиям-рекомендуется-первым)

Для Phase 3 конкретно:

| Машина | Фокус | Флаги |
|---|---|---|
| A | Широкий поиск, crash injection | `-use_value_profile=1` |
| B | Глубокие цепочки (много голосов per iteration) | `-mutate_depth=8 -max_len=200` |
| C | Короткие targeted seeds — quorum scenarios | `n_messages=3, все голоса за один слот` |
| D | Только crash+restart, нет обычных iteration | `do_crash=1` всегда |

### Координатор на Redis (Уровень 3)

→ Описание в [FUZZING_DISTRIBUTED.md — Уровень 3](FUZZING_DISTRIBUTED.md#уровень-3--distributed-directed-fuzzing-координатор)

Применять если Шаг 3 (VectorDB) не даёт новых крашей за 72 часа.

---

## Инварианты для Phase 3

| Инвариант | Cypher query | Требует | Статус |
|---|---|---|---|
| dual-cert (notar+skip) | [#dual-cert](CYPHER_QUERIES.md#dual-cert) | `g_notar_by_slot` + `g_skip_by_slot` | ✅ реализован (Phase 2) |
| alarm-skip-after-notarize | [#alarm-skip-after-notarize](CYPHER_QUERIES.md#alarm-skip-after-notarize) | Consensus актор + crash | 🔲 Шаг 2 |
| amnesia-gap | [#amnesia-gap](CYPHER_QUERIES.md#amnesia-gap) | crash_losing(ourVote) + bootstrap replay | ✅ частично (Phase 2 Шаг 3) |
| two-cert для разных кандидатов | [#dual-cert-issued](CYPHER_QUERIES.md#dual-cert-issued) | `g_notar_by_slot[X]` != new hash | ✅ реализован (Phase 2) |

---

## Порядок работы

```
Phase 2 завершена → code coverage исчерпан (cov: 795)
        ↓
Phase 3 Шаг 1 ✅: state-vector counters + value-profile (ft: 1950)
        ↓
Phase 3 Шаг 2: добавить Consensus актор → alarm-skip путь открыт
        ↓ (если плато)
Phase 3 Шаг 3: VectorDB guidance → gradient descent к опасным состояниям
        ↓ (при наличии нескольких машин, параллельно)
Phase 3 Шаг 4: corpus sync + специализация стратегий
        ↓ (если 72ч без крашей)
        → Распределённый координатор (FUZZING_DISTRIBUTED.md Уровень 3)
```
