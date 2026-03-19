# ConsensusHarness — сборка, запуск и Byzantine сценарии

> Официальные инструкции сборки TON для Windows: [ton-blockchain/ton — Windows 10/11](https://github.com/ton-blockchain/ton#windows-10-11-server-x86-64).
> Первичная настройка (cmake configure, Windows fixes) — **[SETUP.md](SETUP.md)**.

---

## Архитектура (`simulation/ConsensusHarness.cpp`)

`ConsensusHarness` — мок tdactor runtime, запускающий несколько экземпляров `ConsensusImpl`
в одном процессе с управляемым network layer.

```
ConsensusHarness
├── N × ValidatorNode (оборачивает Bus + ConsensusImpl)
│     └── Bus::publish<BroadcastVote> → перехватывается NetworkMock
├── NetworkMock
│     ├── честная доставка (shuffle + latency)
│     └── Byzantine injection (drop, duplicate, substitute)
└── GraphLogger::instance() — общий для всех узлов
```

**Параметры по умолчанию:**
- `N = 4` валидатора (f=1, порог нотаризации ≥ 3)
- `slots_per_leader_window = 4`
- `first_block_timeout_ms = 1000`

---

## Сборка

```bash
# Только simulation-цель (быстро):
cmake --build build --target simulation -j4

# Только ConsensusHarness:
cmake --build build --target ConsensusHarness -j4
```

**Когда нужен полный cmake-reconfigure:**

```
изменения, требующие cmake -B build
├── simulation/CMakeLists.txt
├── CMakeLists.txt (корневой)
├── добавление новых .cpp файлов
└── изменение флагов компиляции
```

> Для правок внутри существующих `.cpp`/`.h` достаточно `cmake --build`.

---

## Запуск сценария

```bash
# Из корня tonGraph/
GRAPH_LOGGING_ENABLED=1 \
GRAPH_LOG_FILE=simulation/trace.ndjson \
./build/simulation/ConsensusHarness --scenario equivocation

# Доступные сценарии:
#   equivocation        — Byzantine валидатор голосует дважды
#   message_withholding — лидер удерживает propose
#   byzantine_leader    — лидер шлёт разные кандидаты
#   all                 — все сценарии подряд

# С расширенным логированием:
./build/simulation/ConsensusHarness --scenario equivocation --log-level DEBUG
```

Бинарь записывает `simulation/trace.ndjson`.

---

## Отправка трейса в Neo4j (relay.mjs)

```bash
node simulation/relay.mjs
```

Читает `simulation/trace.ndjson` построчно и отправляет события через `AuraGraphReporter`.
Требует заполненного `.env` (см. [MCP_NEO4J_AURA.md](MCP_NEO4J_AURA.md)).

---

## Полный workflow прогона

```
1. cmake --build build --target simulation -j4
2. rm simulation/trace.ndjson             # очистка предыдущего трейса
3. GRAPH_LOGGING_ENABLED=1 ./build/simulation/ConsensusHarness --scenario equivocation
4. node simulation/relay.mjs              # отправка трейса в Neo4j
5. MCP-запрос через агента:
     #last-session   — весь граф прогона
     #equivocation   — поиск аномалии
```

Cypher-запросы: **[CYPHER_QUERIES.md](CYPHER_QUERIES.md)**.
Очистить граф: [#clean](CYPHER_QUERIES.md#clean).

---

## Сценарии

### Сценарий 1 — Equivocation

**Условие:** Byzantine валидатор (idx=0) подписывает два `NotarizeVote` с разными `candidateId`
за один и тот же `slot`.

```cpp
harness.set_byzantine(0, ByzantineMode::DoubleVote);
harness.run_slots(10);
```

**Ожидаемые узлы в графе:**
- Два `Candidate` с одинаковым `slot`, разными `candidateId`.
- Два ребра `[:notarize]` от одного `Validator` (idx=0) к разным `Candidate`.

**Проверка:** [CYPHER_QUERIES.md#equivocation](CYPHER_QUERIES.md#equivocation) → ≥ 1 строка.

---

### Сценарий 2 — Message withholding

**Условие:** лидер генерирует кандидата, но `NetworkMock` не доставляет его валидаторам.
Все шлют `SkipVote` по таймауту.

```cpp
harness.set_network_rule(0 /* leader_slot */, NetworkRule::DropPropose);
harness.run_slots(5);
```

**Ожидаемые узлы в графе:**
- `Candidate` с `slot=0` есть (propose зафиксирован у лидера).
- Нет рёбер `[:receive]` или `[:notarize]` от других валидаторов.
- Есть рёбра `[:skip]` от валидаторов 1–3.

**Проверка:** [CYPHER_QUERIES.md#withholding](CYPHER_QUERIES.md#withholding) → ≥ 1 строка.

---

### Сценарий 3 — Byzantine leader

**Условие:** лидер (idx=0) эмитит два разных кандидата (`cand_A` и `cand_B`) для разных
подмножеств валидаторов в одном `slot`. Ни одна группа не набирает кворум.

```cpp
harness.set_byzantine(0, ByzantineMode::SplitPropose{.group_a = {1, 2}, .group_b = {3}});
harness.run_slots(8);
```

**Ожидаемые узлы в графе:**
- Два `Candidate` с одинаковым `leaderIdx=0` и `slot`, разными `candidateId`.
- Рёбра `[:receive]` ведут к разным `Candidate` для разных валидаторов.

**Проверка:** [CYPHER_QUERIES.md#byzantine-leader](CYPHER_QUERIES.md#byzantine-leader) → ≥ 1 строка.

---

## CI

```bash
cmake --build build --target simulation -j4
./build/simulation/ConsensusHarness --scenario all --assert-anomalies
# Возвращает non-zero exit code, если аномалии не найдены
```

---

## Известные проблемы сборки (Windows / MSVC)

### C1128 — `number of sections exceeds object file format limit`

Затронутые файлы: `tl/generate/auto/tl/ton_api.cpp`, `validator/manager.cpp`.

```
error C1128: число секций превышает предел формата объектного файла:
             компилировать с /bigobj
```

**Причина:** автогенерированные TL-файлы слишком велики для MSVC без `/bigobj`.
**Не наш код** — ошибка существовала до инструментации GraphLogger.
**Обходной путь:** добавить `/bigobj` в CMakeLists для таргетов `tl_api`, `validator`.

> Пока `/bigobj` не добавлен — `--target validator` завершается с ошибкой.
> Это **не мешает** сборке `simulation`.

### Изолированная проверка одного .cpp

```powershell
& "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\amd64\MSBuild.exe" `
  "C:\GitHub\tonGraph\build\validator\validator.vcxproj" `
  /t:ClCompile `
  /p:Configuration=Debug `
  /p:Platform=x64 `
  "/p:SelectedFiles=consensus\simplex\pool.cpp" `
  /v:n
```

Несколько файлов через `;`:
```
"/p:SelectedFiles=consensus\simplex\pool.cpp;../simulation/GraphLogger.cpp"
```

### Отладка сборки

```powershell
cmake --build build --target simulation 2>&1 | Select-String " error "
Test-Path build/simulation/ConsensusHarness.exe
```

---

## Очистка

```bash
rm simulation/trace.ndjson
# PowerShell:
Remove-Item simulation/trace.ndjson -ErrorAction SilentlyContinue
```

> Не забудь очистить граф в Neo4j: [CYPHER_QUERIES.md#clean](CYPHER_QUERIES.md#clean).
