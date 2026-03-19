# Сборка на Windows (VS 2022)

Для разработки simulation/ и ConsensusHarness — достаточно Windows.
Для интеграционных тестов (`test_basic.py`) — нужен WSL: **[SETUP_WSL.md](SETUP_WSL.md)**.

---

## Configure и сборка

```bash
# Из корня tonGraph/ — через PowerShell с vcvars64
$env:PATH = 'C:\Strawberry\perl\bin;' + $env:PATH
cmd /c '"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" && cmake -B build -DWITH_SIMULATION=ON'

# Сборка simulation:
cmake --build build --target simulation -j8
```

**Флаги CMake:**

| Флаг | Назначение |
|---|---|
| `-DWITH_SIMULATION=ON` | Включает цель `ConsensusHarness` |
| `-DCMAKE_BUILD_TYPE=Debug` | Символы для lldb/gdb |

> `GRAPH_LOGGING_ENABLED` — env-переменная (не CMake-флаг), управляет записью трассы в runtime.

Время configure: ~6 минут (OpenSSL + zlib собираются при первом запуске).

---

## Известные проблемы

### 1. OpenSSL: неправильный Perl

**Симптом:**
```
Can't locate Locale/Maketext/Simple.pm in @INC
CMake Error at CMake/BuildOpenSSL.cmake:127: OpenSSL config failed with code 2
```

**Причина:** CMake подхватывает Git Bash Perl (`C:\Program Files\Git\usr\bin\perl.exe`), которому не хватает модулей CPAN.

**Решение:** Strawberry Perl (`C:\Strawberry\perl\bin`) **первым** в `PATH` — как в команде выше.

---

### 2. zlib: тулсет v142 (VS 2019) не найден

**Симптом:**
```
error MSB8020: Cannot find build tools for Visual Studio 2019 (PlatformToolset = "v142")
CMake Error at CMake/BuildZlib.cmake:51: Zlib build failed with code 1
```

**Причина:** `CMake/BuildZlib.cmake` жёстко прописывает `v142`, которого нет в VS 2022.

**Решение:** в `CMake/BuildZlib.cmake` заменить оба вхождения `v142` → `v143`.

> Изменение уже внесено в репо.

---

### 3. C1128 — `number of sections exceeds object file format limit`

Затронутые файлы: `tl/generate/auto/tl/ton_api.cpp`, `validator/manager.cpp`.

```
error C1128: число секций превышает предел формата объектного файла:
             компилировать с /bigobj
```

**Причина:** автогенерированные TL-файлы слишком велики для MSVC без `/bigobj`.
**Не наш код** — ошибка существовала до инструментации GraphLogger.

**Обходной путь:** добавить `/bigobj` в CMakeLists для таргетов `tl_api`, `validator`.

> Пока не исправлено — `--target validator` завершается с ошибкой. Сборка `simulation` работает.

---

### 4. Изолированная проверка одного .cpp

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

---

### 5. Почему `test_basic.py` не работает на Windows

`tontester` рассчитан на Linux/macOS. Три блокера:

**Блокер 1 — `tonlibjson` (критический):**
```python
# test/tontester/src/tontester/install.py:55-60
if sys.platform.startswith("linux"):
    name = "tonlib/libtonlibjson.so"
elif sys.platform == "darwin":
    name = "tonlib/libtonlibjson.dylib"
else:
    raise RuntimeError(f"Unsupported platform: {sys.platform}")
```
На Windows бросает `RuntimeError: Unsupported platform: win32`.

**Блокер 2 — бинари не собраны:**
Тест запускает `validator-engine`, `dht-server`, `generate-random-id`, `create-state`.
Они не собираются из-за C1128.

**Блокер 3 — `tonapi` (решён):**
`uv run python test/tontester/generate_tl.py` отрабатывает без ошибок.

**Решение:** использовать WSL → **[SETUP_WSL.md](SETUP_WSL.md)**.

---

## Отладка сборки

```powershell
cmake --build build --target simulation 2>&1 | Select-String " error "
Test-Path build/simulation/ConsensusHarness.exe
```
