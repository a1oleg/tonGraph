# Сборка и интеграционные тесты в WSL

WSL нужен для запуска `test/integration/test_basic.py` — `tontester` работает только на Linux.
Для разработки simulation/ на Windows — **[SETUP_WINDOWS.md](SETUP_WINDOWS.md)**.

---

## Установка WSL

### Шаг 1 — Включить WSL

```powershell
# PowerShell от имени администратора
wsl --install
# Устанавливает Ubuntu 24.04 LTS. После — перезагрузка обязательна.
```

Если WSL уже установлен без дистрибутива:
```powershell
wsl --install -d Ubuntu-24.04
```

### Шаг 2 — Первый запуск

После перезагрузки — окно Ubuntu, задать имя пользователя и пароль.

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

### Шаг 5 — uv

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
source ~/.bashrc
```

### Шаг 6 — Доступ к репозиторию

Репо доступно из WSL по `/mnt/c/GitHub/tonGraph`.

> **Совет:** производительность сборки в WSL-FS в 5–10× выше, чем на `/mnt/c/`:
> ```bash
> cp -r /mnt/c/GitHub/tonGraph ~/tonGraph
> cd ~/tonGraph
> ```

### Шаг 7 — Сборка TON в WSL

```bash
cd ~/tonGraph

cmake -B build-linux \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=clang-18 \
  -DCMAKE_CXX_COMPILER=clang++-18 \
  -G Ninja

cmake --build build-linux \
  --target validator-engine dht-server generate-random-id create-state tonlibjson \
  -j$(nproc)

# tontester ищет build/, а не build-linux/
ln -sfn build-linux build
```

> Не указывать `-DTON_USE_ROCKSDB=OFF`, `-DUSE_QUIC=OFF`, `-DOPENSSL_ROOT_DIR` — вызовет ошибки.

Ожидаемый результат:
```
build-linux/validator-engine/validator-engine   ✓
build-linux/dht-server/dht-server               ✓
build-linux/utils/generate-random-id            ✓
build-linux/crypto/create-state                 ✓
build-linux/tonlib/libtonlibjson.so             ✓
```

### Шаг 8 — Зависимости tontester

```bash
cd ~/tonGraph
uv sync --all-packages
```

---

## Запуск интеграционного теста

```bash
# 1. Сгенерировать tonapi (если ещё не сделано)
uv run python test/tontester/generate_tl.py

# 2. Включить графовое логирование (абсолютный путь!)
export GRAPH_LOGGING_ENABLED=1
export GRAPH_LOG_FILE=$(pwd)/simulation/trace.ndjson

# 3. Запустить тест (таймаут 5 мин — ждёт первый masterchain-блок)
uv run python test/integration/test_basic.py

# 4. Исправить CRLF в .env (если .env создан на Windows)
sed -i 's/\r//' .env

# 5. Отправить трассу в Neo4j
cd simulation && node relay.mjs && cd ..
```

---

## Что даёт реальный трафик

После успешного `test_basic.py` в `trace.ndjson` появятся события от двух настоящих
валидаторов, договаривающихся о первом masterchain-блоке:

- `VoteCast` из `pool.cpp` по реальному сетевому протоколу
- `LeaderWindow`, `AlarmSkip`, `CandidateReceived` из `consensus.cpp`
- `VoteIntentSet` / `VoteIntentPersisted` из `db.cpp`
- `MsgReceived` — счётчики входящих сообщений per validator

После `relay.mjs` можно запускать аномалийные запросы из [CYPHER_QUERIES.md](CYPHER_QUERIES.md)
на живых данных — в частности `#alarm-skip-after-notarize` и `#amnesia-gap`.

---

## Известные проблемы

### Производительность на `/mnt/c/`

Файловые операции через 9P-протокол на `/mnt/c/` медленнее в 5–10× по сравнению с WSL-FS.
Для сборки TON (10 000+ файлов) — критично. Работать в `~/tonGraph`.

### Порты для relay.mjs

`relay.mjs` подключается к Neo4j Aura по `neo4j+s://` (порт 7687).
WSL имеет доступ к интернету по умолчанию, дополнительной настройки не требует.

### CRLF в .env

`.env` с Windows line endings ломает `relay.mjs` в WSL:
```bash
sed -i 's/\r//' .env
```
