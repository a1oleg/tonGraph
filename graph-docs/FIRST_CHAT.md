# Первый чат: графовое логирование для поиска уязвимостей TON Consensus

### Ограничения

- **Текущий `AuraGraphReporter`** привязан к browser runtime (`self.constructor.name`, webpack `APP_REVISION`) — нужна адаптация под C++/standalone
- **Масштаб**: consensus fuzzing генерирует миллионы событий — нужен batch-optimized pipeline (существующий `flushLoop` с batch size 500 — хороший старт, но может потребовать увеличения)
- **Детерминизм**: для воспроизведения бага нужно логировать seed рандома и порядок сообщений
---


### 1. Готовые тест-кейсы в самом репозитории TON

```
ton/
  validator/tests/
  validator/consensus/  ← state machine, message handlers
  crypto/test/
```

В репозитории есть `ton/validator/tests/test-validator.cpp` и аналоги — первый источник: уже описанные сценарии, которые надо прогнать **с инструментацией**, чтобы получить baseline-граф нормального исполнения. Baseline — точка отсчёта. Любое отклонение от него в последующих прогонах — кандидат на уязвимость.

### 2. Fuzzing с libFuzzer / AFL++ (главный источник)

TON использует C++ — идеально ложится на coverage-guided fuzzing:

```cpp
// Обёртка для libFuzzer
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Десериализуем данные как ValidatorSessionMessage
  // → прогоняем через state machine
  // → граф-логгер пишет trace в Neo4j
  return 0;
}
```

**Что фаззить конкретно:**
1
| Точка входа | Класс уязвимостей |
|---|---|
| `ValidatorSessionImpl::process_message()` | Неверная обработка неизвестных типов сообщений |
| `SentBlocks::approve_block()` | Race / double-approve |
| `RoundAttempt::make_vote()` | Equivocation detection bypass |
| Десериализация `td::BufferSlice` | Memory corruption при malformed input |

Corpus для fuzzer берётся из:
- Перехваченных реальных сообщений с testnet (через ADNL-трейс)
- Сгенерированных мутаций из существующих unit-тестов


### 4. Дифференциальное тестирование против эталонной реализации

HotStuff (на котором основан TON consensus) имеет несколько реализаций:
- **LibraBFT / DiemBFT** (Rust) — эталон
- **Tendermint** (Go) — другая BFT-семья, для сравнения поведения corner cases

Взять одинаковый входной сценарий → прогнать через TON и через эталон → сравнить графы в Neo4j:

```cypher
// Найти состояния, достигнутые в TON но не в эталоне
MATCH (n:ConsensusState {implementation: 'ton'})
WHERE NOT EXISTS {
  MATCH (m:ConsensusState {implementation: 'reference', stateHash: n.stateHash})
}
RETURN n
```


### 6. TLA+ / Alloy спецификации

Если у TON есть формальная спецификация (или если написать её по коду), model checker генерирует **все достижимые состояния** автоматически. Каждая контрпримерная трасса из TLA+ — один прогон для граф-логгера.

### Итоговая приоритизация

```
1. [БЫСТРО] Прогнать существующие unit-тесты TON с инструментацией → baseline граф
2. [БЫСТРО] Вручную воспроизвести 3-4 BFT-сценария из таблицы выше → аномалии
3. [СРЕДНЕ] Настроить libFuzzer на process_message() → корпус интересных входов
4. [ДОЛГО]  Дифференциальное тестирование против LibraBFT
```

Самый быстрый способ найти что-то конкретное — **шаг 2**: написать adversarial harness на C++, где один из `f` валидаторов ведёт себя по-Byzantine согласно сценарию из таблицы, прогнать, посмотреть граф в Neo4j Browser.

---

## Архитектура: форк + simulation/ модуль

### Структура репозитория

```
ton/ (форк)
  validator/consensus/     ← инструментируем здесь
  simulation/              ← новая папка
    ConsensusHarness.cpp   ← мок actor runtime + Byzantine scenarios
    GraphLogger.cpp        ← C++ аналог WorkerGraphReporter
    GraphLogger.h
    scenarios/
      equivocation.cpp
      message_withholding.cpp
      byzantine_leader.cpp
    CMakeLists.txt
```


### Что инструментировать первым

Три файла дают 80% coverage консенсусной логики:

| Файл | Ключевые функции | Уязвимость |
|---|---|---|
| `validator-session-round-attempt.cpp` | `make_vote()`, `make_precommit()` | Equivocation |
| `validator-session-state.cpp` | `apply_action()`, `try_approve_block()` | State divergence |
| `validator-session.cpp` | `process_message()`, `on_new_round()` | Message reordering, liveness |

### Итого

```
1. fork ton-blockchain/ton → свой репо
2. создать simulation/ с GraphLogger.cpp (~100 строк)
3. написать ConsensusHarness.cpp — мок actor runtime (без реального ADNL)
4. инструментировать 3 файла выше вызовами GraphLogger::logCall()
5. relay.mjs → AuraGraphReporter → Neo4j
6. Cypher-запросы из CYPHER_QUERIES.md — без изменений
```
