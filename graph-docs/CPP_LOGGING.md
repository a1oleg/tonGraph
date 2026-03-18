# C++ GraphLogger — граф-логирование из консенсус-потока

`GraphLogger` — потокобезопасный fire-and-forget логгер. Эмитирует NDJSON-строки
в файл; `relay.mjs` читает файл и загружает события в Neo4j Aura.

---

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

Consensus-поток **не ждёт** записи в Neo4j. `GraphLogger` пишет в файл синхронно,
но с мьютексом — безопасно из нескольких tdactor-потоков.

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

**Инициализация** — `init()` вызывается один раз в `main()` каждого процесса:

```cpp
// validator-engine/validator-engine.cpp и validator/consensus/bridge.cpp
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

Порядок ключей: сначала именованные поля из `props` (в алфавитном порядке `std::map`),
затем `tsMs`.

---

## Пример инструментации

```cpp
// validator/consensus/simplex/pool.cpp — эмит VoteCast
#include "simulation/GraphLogger.h"

simulation::GraphLogger::instance().emit("VoteCast", {
    {"candidateId", id.hash.to_hex()},
    {"sessionId",   owning_bus()->session_id.to_hex()},
    {"slot",        static_cast<int64_t>(id.slot)},
    {"validatorIdx", static_cast<int64_t>(local_idx.value())},
    {"voteType",    std::string("notarize")},
});
```

```cpp
// validator/consensus/block-accepter.cpp — эмит BlockAccepted
simulation::GraphLogger::instance().emit("BlockAccepted", {
    {"candidateId", event->candidate->id.hash.to_hex()},
    {"sessionId",   owning_bus()->session_id.to_hex()},
    {"slot",        static_cast<int64_t>(event->candidate->id.slot)},
});
```

---

## Все события (по файлам)

### `simplex/consensus.cpp`

| Событие | Поля | Когда |
|---|---|---|
| `LeaderWindow` | `localIdx`, `startSlot`, `endSlot`, `sessionId` | Валидатор стал лидером |
| `AlarmSkip` | `slot`, `votedFinal`, `votedNotar`, `sessionId` | `alarm()` сработал — потенциальный SkipVote |
| `CandidateDuplicate` | `slot`, `leaderIdx`, `existingCandId`, `newCandId`, `receiverIdx`, `sessionId` | Лидер прислал второй кандидат на тот же слот |
| `CandidateReceived` | `slot`, `candidateId`, `leaderIdx`, `parentSlot`, `receiverIdx`, `sessionId` | Валидатор получил кандидата |
| `VoteIntentSet` | `slot`, `candidateId`, `persisted`, `sessionId` | Намерение голосовать записано в памяти |

### `simplex/db.cpp`

| Событие | Поля | Когда |
|---|---|---|
| `VoteIntentPersisted` | `slot`, `persisted`, `sessionId` | WAL успешно записал намерение |
| `DBWriteFailure` | `slot`, `sessionId` | Ошибка записи в WAL |

### `simplex/pool.cpp`

| Событие | Поля | Когда |
|---|---|---|
| `BootstrapVoteReplayed` | `slot`, `validatorIdx`, `sessionId` | При рестарте воспроизведён сохранённый голос |
| `MsgReceived` | `slot`, `sourceIdx`, `localIdx`, `msgType`, `sessionId` | Входящее сообщение (vote/cert/candidate) |
| `InvariantViolation` | `slot`, `validatorIdx`, `voteType`, `sessionId` | Нарушение инварианта в `check_invariants()` |
| `ConflictTolerated` | `slot`, `validatorIdx`, `voteType`, `sessionId` | Конфликт принят с `tolerate_conflicts=true` |
| `VoteCast` | `slot`, `candidateId`, `validatorIdx`, `voteType`, `sessionId` | Голос отправлен в сеть |
| `ResourceLoad` | `slot`, `notarizeWeightEntries`, `pendingRequests`, `sessionId` | Снапшот нагрузки после VoteCast |
| `CertIssued` | `slot`, `certType`, `candidateId`, `weight`, `sessionId` | Сертификат набрал кворум (notarize/finalize/skip) |

### `consensus/block-accepter.cpp`

| Событие | Поля | Когда |
|---|---|---|
| `BlockAccepted` | `slot`, `candidateId`, `sessionId` | Блок принят менеджером (`accept_block` завершён) |

---

## Добавление нового события

1. Найди нужное место в C++ (обработчик tdactor).
2. Добавь `#include "simulation/GraphLogger.h"` (путь относительно `INCLUDE_DIRECTORIES`).
3. Вызови:
   ```cpp
   simulation::GraphLogger::instance().emit("МоёСобытие", {
       {"sessionId", owning_bus()->session_id.to_hex()},
       {"slot",      static_cast<int64_t>(slot)},
       // ... другие поля
   });
   ```
4. В `relay.mjs` добавь обработчик в `dispatch()`:
   ```js
   case 'МоёСобытие': return handleMyEvent(session, ev);
   ```
5. При необходимости добавь Cypher-запрос в `CYPHER_QUERIES.md`.

> **Типы PropVal:** `std::string`, `int64_t`, `double`, `bool`.
> Для hex-строк (`candidateId`, `sessionId`) используй `.to_hex()` / `std::string(...)`.
> Для числовых индексов — `static_cast<int64_t>(...)`.

---

## Известные ограничения

- `tsMs` берётся из `std::chrono::system_clock` (wall time), а не из tdactor-таймера.
  При сдвиге системных часов возможна инверсия меток. Для отладки порядка событий
  внутри одного потока использовать монотонные метки нельзя (нет экспорта).
- Файл открывается в режиме `"w"` (перезапись) при каждом `init()` — каждый запуск
  процесса перезаписывает трассу. При двух валидаторах оба пишут в один файл
  с мьютексом — строки не перемешиваются, но порядок между процессами не детерминирован.
- `relay.mjs` обрабатывает файл однократно (batch mode). Режима tail-f нет.
