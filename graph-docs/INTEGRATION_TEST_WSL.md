# Интеграционные тесты и WSL

Цель: запустить `test/integration/test_basic.py` для получения реального трафика консенсуса
и проверки графового логирования на живых данных.

---

## Почему тест не работает на Windows

`test/integration/test_basic.py` использует фреймворк `tontester`, который рассчитан на Linux/macOS.

### Блокер 1 — `tonlibjson` (критический)

`test/tontester/src/tontester/install.py:55-60`:

```python
if sys.platform.startswith("linux"):
    name = "tonlib/libtonlibjson.so"
elif sys.platform == "darwin":
    name = "tonlib/libtonlibjson.dylib"
else:
    raise RuntimeError(f"Unsupported platform: {sys.platform}")
```

На Windows бросает `RuntimeError: Unsupported platform: win32` сразу при инициализации.
`tonlibjson.dll` не собирается CMake-конфигурацией для Windows.

### Блокер 2 — бинари не собраны

Тест запускает реальные процессы. `install.py` ожидает:

| Путь в build/ | Что это |
|---|---|
| `validator-engine/validator-engine` | Основной валидатор |
| `dht-server/dht-server` | DHT-нода |
| `utils/generate-random-id` | Генератор ключей |
| `crypto/create-state` | Fift-интерпретатор |

Сейчас в `build/` собраны только `simulation/Debug/ConsensusHarness.exe` и `crypto/Debug/tlbc.exe`.
Остальные не собраны из-за ошибки C1128 (`/bigobj`) на крупных TU (см. `BUILD_AND_RUN.md`).

### Блокер 3 — `tonapi` не сгенерирован (решён)

`test/tontester/src/tonapi/` изначально пустая — требует запуска `generate_tl.py`.
**Уже исправлено:** `uv run python test/tontester/generate_tl.py` отрабатывает без ошибок,
файлы `ton_api.py`, `lite_api.py`, `tonlib_api.py` созданы.

---

## Порядок запуска после установки WSL

После выполнения шагов ниже:

```bash
# 1. Войти в WSL-дистрибутив
wsl

# 2. Из корня репо собрать нужные таргеты
cd /mnt/c/GitHub/tonGraph
cmake -B build-linux -DCMAKE_BUILD_TYPE=Release
cmake --build build-linux --target validator-engine dht-server generate-random-id create-state -j$(nproc)

# 3. Сгенерировать tonapi (если ещё не сделано)
uv run python test/tontester/generate_tl.py

# 4. Включить графовое логирование
export GRAPH_LOGGING_ENABLED=1
export GRAPH_LOG_FILE=simulation/trace.ndjson

# 5. Запустить тест (5 мин таймаут)
uv run python test/integration/test_basic.py

# 6. Отправить трассу в Neo4j
node simulation/relay.mjs --clear simulation/trace.ndjson
```

---

## Установка WSL

### Шаг 1 — Включить WSL и виртуализацию

```powershell
# PowerShell от имени администратора
wsl --install
# По умолчанию устанавливает Ubuntu 24.04 LTS
# После — перезагрузка обязательна
```

Если WSL уже установлен, но без дистрибутива:

```powershell
wsl --install -d Ubuntu-24.04
```

### Шаг 2 — Первый запуск Ubuntu

После перезагрузки откроется окно Ubuntu — задать имя пользователя и пароль.

### Шаг 3 — Зависимости сборки TON

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y \
  build-essential cmake ninja-build git \
  libssl-dev zlib1g-dev libsecp256k1-dev \
  libmicrohttpd-dev libsodium-dev \
  clang-18 libc++-18-dev libc++abi-18-dev \
  python3 python3-pip curl
```

### Шаг 4 — Node.js (для relay.mjs)

```bash
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt install -y nodejs
```

### Шаг 5 — uv (Python пакетный менеджер)

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
source ~/.bashrc
```

### Шаг 6 — Доступ к репозиторию

Репозиторий уже лежит на Windows-диске и доступен из WSL по пути `/mnt/c/GitHub/tonGraph`.

```bash
cd /mnt/c/GitHub/tonGraph
# Проверка
ls simulation/relay.mjs
```

> **Совет:** производительность сборки значительно выше если скопировать репо в WSL-файловую систему:
> ```bash
> cp -r /mnt/c/GitHub/tonGraph ~/tonGraph
> cd ~/tonGraph
> ```

### Шаг 7 — Сборка TON в WSL

```bash
cd ~/tonGraph   # или /mnt/c/GitHub/tonGraph

cmake -B build-linux \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=clang-18 \
  -DCMAKE_CXX_COMPILER=clang++-18 \
  -DTON_USE_ROCKSDB=OFF \
  -G Ninja

cmake --build build-linux \
  --target validator-engine dht-server generate-random-id create-state \
  -j$(nproc)
```

Ожидаемый результат:
```
build-linux/validator-engine/validator-engine   ✓
build-linux/dht-server/dht-server               ✓
build-linux/utils/generate-random-id            ✓
build-linux/crypto/create-state                 ✓
build-linux/tonlib/libtonlibjson.so             ✓
```

### Шаг 8 — Установить зависимости tontester

```bash
cd ~/tonGraph
uv sync --all-packages
# или напрямую:
cd test/tontester
uv pip install -e .
```

---

## Что даст реальный трафик

После успешного `test_basic.py` в `simulation/trace.ndjson` появятся события от двух настоящих
валидаторов (`FullNode.make_initial_validator()`), договаривающихся о первом masterchain-блоке.

В отличие от `ConsensusHarness`, это:
- Настоящие `VoteCast` события из `pool.cpp` по реальному сетевому протоколу
- `LeaderWindow`, `AlarmSkip`, `CandidateReceived` из `consensus.cpp`
- `VoteIntentSet` / `VoteIntentPersisted` из `db.cpp`
- `MsgReceived` счётчики входящих сообщений per validator

После `relay.mjs --clear` в Neo4j можно запускать аномалийные Cypher-запросы из
`CYPHER_QUERIES.md` на живых данных — в частности `#alarm-skip-after-notarize` и `#amnesia-gap`.

---

## Известные проблемы WSL

### Производительность на `/mnt/c/`

Файловые операции через 9P-протокол на `/mnt/c/` медленнее в 5–10× по сравнению с нативной
WSL-файловой системой. Для сборки TON (10 000+ файлов) это критично.
**Решение:** работать в `~/tonGraph` (WSL-FS), синхронизировать через `git`.

### Порты для Neo4j relay.mjs

`relay.mjs` подключается к Neo4j Aura по `neo4j+s://` — это HTTPS/WebSocket через порт 7687.
WSL имеет доступ к интернету по умолчанию, дополнительной настройки не требует.

### Переменные окружения из .env

`.env` лежит в корне репо с Windows line endings (CRLF) — в WSL это может сломать `relay.mjs`.
Перед запуском:

```bash
sed -i 's/\r//' .env
```

> Подробнее — `MCP_NEO4J_AURA.md#известные-проблемы`.
