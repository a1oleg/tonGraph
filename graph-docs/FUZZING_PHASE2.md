# Фаззинг — Phase 2: уровень реализации

[← Phase 1](FUZZING_PHASE1.md) | [Общий план](FUZZING_PLAN.md) | [→ Phase 3](FUZZING_PHASE3.md)

## Что фаззим

Реальный `pool.cpp` через actor runtime.
Находит баги в **реализации** — TL-десериализация, integer overflow, use-after-free,
WAL-состояния.

В отличие от Phase 1 (модель, N≤6), здесь пространство состояний ~2^64.

---

## Текущий прогресс

```
Шаг 1  ✅  fuzz_tl       — TL-парсинг 9 wire-типов (без actor runtime)
Шаг 2  ✅  fuzz_pool     — pool.cpp через BusRuntime + MockDb
Шаг 3  ✅  WAL crash injection (интегрирован в fuzz_pool)
```

---

## Шаг 1 — fuzz_tl ✅

**Что тестирует:** `fetch_tl_object` для 9 TL-типов simplex consensus:
`vote`, `certificate`, `voteSignatureSet`, `voteSignature`, `candidateAndCert`,
DB-типы (`ourVote`, `cert`, `poolState`, `finalizedBlock`).

**Что ловит:** buffer overflow, OOB-read, assertion failure в TL-парсере при
приёме любого произвольного байтового потока от пира.

**Что НЕ тестирует:** бизнес-логику pool.cpp, подпись, WAL.

### Сборка

```bash
cmake build -DFUZZING=ON
cmake --build build --target fuzz_tl -- -j$(nproc)
```

### Тестовый прогон (1 час)

> **Важно:** `-max_total_time=3600` — таймер каждого воркера, не всего прогона.
> Главный процесс ждёт пока завершатся все `-jobs=N` воркеров → суммарное время >1 часа.
> Используй `timeout` чтобы прогон длился ровно час:

```bash
REPO=$(pwd)
mkdir -p simulation/corpus_fuzz_tl simulation/crashes_tl
tmux new-session -d -s fuzz_tl \
  "cd $REPO && timeout 3600 ./build/test/consensus/fuzz_tl \
  $REPO/simulation/corpus_fuzz_tl/ \
  -max_total_time=3600 -jobs=$(nproc) \
  -artifact_prefix=$REPO/simulation/crashes_tl/ \
  >> $REPO/simulation/fuzz_tl.log 2>&1"
```

**На что смотреть в результатах тестового прогона:**
- `crashes_tl/` — пусто? Если есть файлы → воспроизвести, понять какой тип упал
- `fuzz_tl.log`: строка `cov:` — coverage растёт первые минуты, потом плато. Плато нормально — TL-парсер небольшой
- Скорость: ожидаемо >500K iter/sec (TL-парсинг без криптографии очень быстрый)
- Если `cov:` плато уже после 10 минут — всё покрыто, можно запускать полный прогон

### Результаты тестового прогона (2026-03-19)

| Параметр | Значение |
|---|---|
| Длительность | ~1 час (16 воркеров, завершён вручную) |
| Итерации (воркер 0) | 1.37 млрд |
| Скорость | ~380K iter/sec |
| Coverage | `cov: 215` — плато с первых минут |
| Corpus | 547 файлов |
| **Крашей** | **0** |

**Вывод:** TL-парсер чист. Coverage плато на `cov: 215` — все ветки покрыты.
Полный 24-часовой прогон не имеет смысла — переходим к Шагу 2 (fuzz_pool).

### Полный прогон (24 часа)

```bash
tmux new-session -d -s fuzz_tl \
  "cd $REPO && timeout 86400 ./build/test/consensus/fuzz_tl \
  $REPO/simulation/corpus_fuzz_tl/ \
  -max_total_time=86400 -jobs=$(nproc) \
  -artifact_prefix=$REPO/simulation/crashes_tl/ \
  >> $REPO/simulation/fuzz_tl.log 2>&1"
```

Смысл полного прогона: TL-парсер покрывается быстро, но редкие крэши в corner case
могут потребовать много итераций. 24 часа = ~50B итераций на 16 воркерах.
Если за 1 час coverage вышло на плато и крашей нет — переходим к Шагу 2,
не ждём 24 часа.

---

## Шаг 2 — fuzz_pool ✅

**Что тестирует:** реальный `PoolImpl` (`pool.cpp`) с настоящим actor runtime,
N=4 validators (dummy keys), `MockDb` (in-memory WAL), `FuzzObserver` (dual-cert oracle).

**Что ловит:** баги в логике накопления голосов, обработке сертификатов,
dual-cert (NotarCert+SkipCert на одном слоте = SAFETY VIOLATION).

**Коммит:** `e7e08519`

**Реализация:** `test/consensus/fuzz_pool.cpp` (~270 строк)
- `MockDb`: in-memory `consensus::Db` (синхронный `co_return {}`)
- `FuzzBus`: extends `simplex::Bus`, `populate_collator_schedule()`
- `FuzzObserver`: actor, отслеживает `NotarizationObserved`/`FinalizationObserved`, `__builtin_trap()` при dual-cert
- `PeerValidator::g_skip_signature_check = true`: обход Ed25519 без изменений prod-кода
- Fuzz input: FuzzedDataProvider → (src_idx, vote_type, slot, cand_seed) × N
- Дрейн: 20 × `scheduler.run(0)` после каждого inject

**Скорость:** **~5K iter/sec** на 1 воркер (actor runtime, BusRuntime overhead)

### Тестовый прогон (1 час)

```bash
REPO=$(pwd)
mkdir -p simulation/corpus_fuzz_pool simulation/crashes_pool
tmux new-session -d -s fuzz_pool \
  "cd $REPO && timeout 3600 ./build/test/consensus/fuzz_pool \
   $REPO/simulation/corpus_fuzz_pool/ \
   -max_total_time=3600 -jobs=$(nproc) \
   -artifact_prefix=$REPO/simulation/crashes_pool/ \
   >> $REPO/simulation/fuzz_pool.log 2>&1"
```

На что смотреть:
- `crashes_pool/` — любой crash важен (dual-cert = `__builtin_trap`)
- `cov:` — должна расти дольше чем у fuzz_tl (pool.cpp сложнее)
- Если coverage плато <1 часа → переходить к полному прогону

### Результаты тестового прогона (2026-03-19)

| Параметр | Значение |
|---|---|
| Длительность | ~5 мин (остановлен вручную по плато) |
| Скорость | ~7-8K iter/sec на воркер |
| Coverage | `cov: 104` — плато с самого старта |
| Corpus | 31 файл |
| **Крашей** | **0** |

**Вывод:** pool.cpp покрыт полностью за секунды после старта. Полный 72-часовой прогон
не имеет смысла — переходим к Шагу 3 (WAL crash injection).

### Полный прогон (72 часа) — пропущен

Coverage плато с первых секунд → полный прогон не даст новых путей.

---

## Шаг 3 — WAL crash injection ✅

**Что тестирует:** `#amnesia-gap` и `#alarm-skip-after-notarize` —
баги которые проявляются только после crash+recover последовательности.

**Что ловит:** safety violation через crash boundary:
`NotarizationObserved` до краша + `SkipCert` после recover → `__builtin_trap()`.

**Коммит:** реализован в рамках шага 2 (тот же `fuzz_pool.cpp`)

**Реализация:** расширение `fuzz_pool.cpp`:
- `MockDb::crash_losing_last_n(n)`: удаляет последние N записей WAL (write_log_)
- `MockDb::clone()`: deep clone состояния для нового bus после краша
- `MockKeyring`: actor, возвращает dummy 64-byte подписи для `bootstrap_votes` replay
- `crash_and_restart(n_lose)`: crash db → clone → drain 200 rounds → reset bus+runtime → new bus
- Fuzz input добавляет: `do_crash:bool`, `n_lose:uint8(0..8)`
- `g_notar_by_slot` / `g_skip_by_slot` **сохраняются** через crash boundary

**Coverage:** `cov: 791` (был 104 без краша — +687 новых путей через restart)

**Скорость:** ~4K iter/sec (crash restart добавляет 200 drain rounds)

### Тестовый прогон (2026-03-19)

| Параметр | Значение |
|---|---|
| Длительность | ~10 мин (остановлен вручную по плато) |
| Скорость | ~3K iter/sec на воркер |
| Coverage | `cov: 795` — плато с первых минут (793 → 795 за 2M итераций) |
| Corpus | 56 файлов |
| **Крашей** | **0** |

**Вывод:** crash-recovery пути покрыты полностью за секунды после старта.
Phase 2 завершена → см. [Phase 3](FUZZING_PHASE3.md).

---

## Инварианты для Phase 2

| Проверка | Cypher query | Как проверять |
|---|---|---|
| alarm-skip-after-notarize | `#alarm-skip-after-notarize` | После WAL recover: votedNotar=true + AlarmSkip → crash |
| Amnesia gap | `#amnesia-gap` | VoteIntentSet записан, WAL crash → после recover vote_intent отсутствует |

Оба требуют `MockDb::crash_and_recover()` — Шаг 3.

---

## Управление plateau (отличие от Phase 1)

В Phase 1 plateau = "всё покрыто, стоп". В Phase 2 пространство состояний ~2^64,
plateau значит "мутатор застрял в локальном минимуме" — **не останавливать, перезапускать:**

| Сигнал | Реакция |
|---|---|
| `ft:` не растёт >1h | Merge corpus + сгенерировать новые targeted seeds |
| `ft:` растёт медленно | Нормально, продолжать |
| Coverage плато, крашей нет | Перейти к следующему шагу |

**Corpus bloat:** периодически минимизировать каждые 4 часа:
```bash
./build/test/consensus/fuzz_pool -merge=1 corpus_pool_min/ corpus_pool/
```
