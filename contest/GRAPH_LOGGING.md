# Граф-логирование консенсуса TON Simplex

## Поток данных

```
consensus-поток (C++, tdactor)
  │
  ├─ GraphLogger::instance().emit("EventName", {key: val, …})
  │     └─ сериализует в JSON-строку
  │     └─ fwrite + fflush → GRAPH_LOG_FILE
  │
relay.mjs (Node.js, запускается вручную)
  │
  ├─ читает trace.ndjson построчно
  │     └─ dispatch(ev) по ev.event
  │           └─ MERGE/CREATE в Neo4j Aura (bolt+s://)
```

Consensus-поток **не ждёт** записи в Neo4j — fire-and-forget через мьютекс.

---

## Архитектура `GraphLogger`

**`simulation/GraphLogger.h`**

```cpp
namespace simulation {

using PropVal = std::variant<std::string, int64_t, double, bool>;
using Props   = std::map<std::string, PropVal>;

class GraphLogger {
 public:
  static GraphLogger& instance();       // singleton
  void init();                          // читает env-переменные, открывает файл
  void emit(const std::string& event_type, const Props& props = {});
  bool is_enabled() const { return enabled_; }

 private:
  bool    enabled_{false};
  FILE*   file_{nullptr};
  std::mutex mu_;
};

}  // namespace simulation
```

**Инициализация** — `init()` вызывается один раз в `main()`:

```cpp
simulation::GraphLogger::instance().init();
```

**Env-переменные:**

| Переменная | По умолчанию | Описание |
|---|---|---|
| `GRAPH_LOGGING_ENABLED` | off | `1` / `true` включает логирование |
| `GRAPH_LOG_FILE` | `simulation/trace.ndjson` | Путь к выходному файлу (лучше абсолютный) |

---

## NDJSON-формат

Одна строка = одно событие. `tsMs` добавляется автоматически на стороне C++.

```json
{"event":"VoteCast","candidateId":"A1B2…","slot":3,"voteType":"notarize","validatorIdx":0,"sessionId":"3B13…","tsMs":1773817640463}
```

---

## Правила инструментации

- Каждому консенсусному событию — своя вершина в графе, уникальный `nodeId`.
- `sessionId` = `bus.session_id` — изолирует один прогон.
- Расширять, не менять: инструментация добавляется внутрь оригинального обработчика, не меняя логики.

**Обязательные поля:**

| Поле | Тип | Источник |
|---|---|---|
| `sessionId` | string | `bus.session_id.to_hex()` |
| `slot` | int64 | номер слота |
| `tsMs` | int64 | добавляется автоматически GraphLogger |
| `validatorIdx` | int64 | `PeerValidatorId::value()` |
| `candidateId` | string | `CandidateId::hash.to_hex()` |
| `voteType` | string | `notarize \| finalize \| skip` |

---

## Схема узлов и рёбер

```
(Validator)-[:propose {slot, tsMs}]->(Candidate)
(Candidate)<-[:notarize {slot, tsMs}]-(Validator)
(Candidate)-[:cert {slot, weight, tsMs}]->(Cert)
(Cert)<-[:finalize {slot, tsMs}]-(Validator)
(Cert)-[:accepted {slot, tsMs}]->(Block)
(Candidate)-[:parent {parentSlot}]->(PrevBlock)
(Validator)-[:skip {slot, tsMs}]->(SkipEvent)
```

Подробно: **[CYPHER_QUERIES.md#edge-types](CYPHER_QUERIES.md#edge-types)**

---

## Точки инструментации

| Файл | Место | Событие | Аномалия |
|---|---|---|---|
| `simplex/consensus.cpp` | `handle(CandidateReceived)` | `CandidateReceived` / `CandidateDuplicate` | Byzantine leader — разные кандидаты разным валидаторам |
| `simplex/consensus.cpp` | `try_notarize()` | `VoteIntentSet` | Equivocation: два notarize за разные candidateId |
| `simplex/consensus.cpp` | `alarm()` | `AlarmSkip` | Liveness: propose без vote дольше timeout |
| `simplex/db.cpp` | WAL write | `VoteIntentPersisted` / `DBWriteFailure` | Amnesia: голос в памяти, но не в WAL |
| `simplex/pool.cpp` | `handle_vote` | `VoteCast`, `ResourceLoad`, `CertIssued` | Equivocation, resource exhaustion |
| `simplex/pool.cpp` | `check_invariants()` | `InvariantViolation`, `ConflictTolerated` | Все конфликты голосов |
| `block-accepter.cpp` | block accepted | `BlockAccepted` | State divergence |

---

## Все события (по файлам)

### `simplex/consensus.cpp`

| Событие | Поля | Когда |
|---|---|---|
| `LeaderWindow` | `localIdx`, `startSlot`, `endSlot`, `sessionId` | Валидатор стал лидером |
| `AlarmSkip` | `slot`, `votedFinal`, `votedNotar`, `sessionId` | `alarm()` сработал |
| `CandidateReceived` | `slot`, `candidateId`, `leaderIdx`, `parentSlot`, `receiverIdx`, `sessionId` | Валидатор получил кандидата |
| `CandidateDuplicate` | `slot`, `leaderIdx`, `existingCandId`, `newCandId`, `receiverIdx`, `sessionId` | Лидер прислал второй кандидат на тот же слот |
| `VoteIntentSet` | `slot`, `candidateId`, `persisted`, `sessionId` | Намерение голосовать записано в памяти |

### `simplex/db.cpp`

| Событие | Поля | Когда |
|---|---|---|
| `VoteIntentPersisted` | `slot`, `persisted`, `sessionId` | WAL успешно записал намерение |
| `DBWriteFailure` | `slot`, `sessionId` | Ошибка записи в WAL |

### `simplex/pool.cpp`

| Событие | Поля | Когда |
|---|---|---|
| `VoteCast` | `slot`, `candidateId`, `validatorIdx`, `voteType`, `sessionId` | Голос отправлен в сеть |
| `CertIssued` | `slot`, `certType`, `candidateId`, `weight`, `sessionId` | Сертификат набрал кворум |
| `ResourceLoad` | `slot`, `notarizeWeightEntries`, `pendingRequests`, `sessionId` | Снапшот нагрузки после VoteCast |
| `MsgReceived` | `slot`, `sourceIdx`, `localIdx`, `msgType`, `sessionId` | Входящее сообщение |
| `InvariantViolation` | `slot`, `validatorIdx`, `voteType`, `sessionId` | Нарушение в `check_invariants()` |
| `ConflictTolerated` | `slot`, `validatorIdx`, `voteType`, `sessionId` | Конфликт принят с `tolerate_conflicts=true` |
| `BootstrapVoteReplayed` | `slot`, `validatorIdx`, `sessionId` | При рестарте воспроизведён сохранённый голос |

### `consensus/block-accepter.cpp`

| Событие | Поля | Когда |
|---|---|---|
| `BlockAccepted` | `slot`, `candidateId`, `sessionId` | Блок принят менеджером |

---

## Добавление нового события

1. Найди нужный обработчик в C++.
2. Добавь `#include "simulation/GraphLogger.h"`.
3. Вызови:
   ```cpp
   simulation::GraphLogger::instance().emit("МоёСобытие", {
       {"sessionId", owning_bus()->session_id.to_hex()},
       {"slot",      static_cast<int64_t>(slot)},
   });
   ```
4. В `relay.mjs` добавь обработчик в `dispatch()`:
   ```js
   case 'МоёСобытие': return handleMyEvent(session, ev);
   ```
5. При необходимости добавь Cypher-запрос в `CYPHER_QUERIES.md`.

> **Типы PropVal:** `std::string`, `int64_t`, `double`, `bool`.

---

## Рабочий цикл

1. Найти точку инструментации (чат или Cypher: [#frontier](CYPHER_QUERIES.md#frontier)).
2. Добавить `emit()` в обработчик.
3. Собрать: `cmake --build ./build --target simulation -j4`.
4. Запустить сценарий: **[SIMULATION.md](SIMULATION.md)**.
5. `node simulation/relay.mjs` → Neo4j.
6. Проверить через MCP ([MCP_NEO4J_AURA.md](mcps/MCP_NEO4J_AURA.md)):
   - Изолировать прогон: [#last-session](CYPHER_QUERIES.md#last-session)
   - Аномалии: [#equivocation](CYPHER_QUERIES.md#equivocation), [#dual-cert](CYPHER_QUERIES.md#dual-cert)
   - Очистить: [#clean](CYPHER_QUERIES.md#clean)

---

## Известные ограничения

- `tsMs` — wall time (`std::chrono::system_clock`), не монотонные часы. При сдвиге системных часов возможна инверсия меток.
- Файл открывается в режиме `"w"` при каждом `init()` — каждый запуск перезаписывает трассу.
- `relay.mjs` обрабатывает файл однократно (batch mode), режима tail-f нет.
- При двух процессах-валидаторах оба пишут в один файл через мьютекс — строки не перемешиваются, но порядок между процессами не детерминирован.
