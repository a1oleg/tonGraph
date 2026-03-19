# Фаззинг — Phase 2: уровень реализации

[← Phase 1](FUZZING_PHASE1.md) | [Общий план](FUZZING_PLAN.md)

## Что фаззим

Реальный `pool.cpp` через actor runtime.
Находит баги в **реализации** — TL-десериализация, integer overflow, use-after-free,
WAL-состояния.

В отличие от Phase 1 (модель, N≤6), здесь пространство состояний ~2^64.

---

## Текущий прогресс

```
Шаг 1  ✅  fuzz_tl       — TL-парсинг 9 wire-типов (без actor runtime)
Шаг 2  🔲  fuzz_pool     — pool.cpp через BusRuntime + MockDb
Шаг 3  🔲  WAL crash injection
Шаг 4  🔲  vector-guided fuzzing (если 1–3 не дали результата)
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

## Шаг 2 — fuzz_pool 🔲

**Что тестирует:** реальный `PoolImpl` (`pool.cpp`) с настоящим actor runtime,
искусственным validator set (без сетевого слоя), MockDb.

**Что ловит:** баги в логике накопления голосов, обработке сертификатов,
WAL-операциях при краше.

**Скорость:** ожидаемо 1K–10K iter/sec (actor runtime значительно медленнее).

### Что нужно написать (~500 строк)

```cpp
// MockDb — WAL без диска, с инжекцией краша
class MockDb : public consensus::Db {
    std::map<std::string, td::BufferSlice> kv_;
public:
    std::optional<td::BufferSlice> get(td::Slice key) const override;
    std::vector<...> get_by_prefix(td::uint32 prefix) const override;
    td::actor::Task<> set(td::BufferSlice key, td::BufferSlice value) override;
    void crash_and_recover();  // сбрасывает несинхронизированные write
};

// Детерминированный validator set с fake-подписями (Ed25519 заменён XOR)
// Инжекция IncomingProtocolMessage из fuzz input
// Дрейн event queue после каждого сообщения
```

### Тестовый прогон (1 час)

На что смотреть:
- `crashes_pool/` — любой crash важен, репортить
- `cov:` — должна расти дольше чем у fuzz_tl (логика сложнее)
- Если coverage плато <1 часа → генерировать targeted seeds из trace.ndjson

### Полный прогон (72 часа)

Pool.cpp сложнее TL-парсера: полный прогон имеет смысл дольше, чем fuzz_tl.
72 часа — разумная верхняя граница до перехода к WAL crash injection.

---

## Шаг 3 — WAL crash injection 🔲

**Что тестирует:** `#amnesia-gap` и `#alarm-skip-after-notarize` —
баги которые проявляются только после crash+recover последовательности.

Добавляется поверх fuzz_pool: `MockDb::crash_and_recover()` вызывается
в случайный момент между сообщениями.

**Полный прогон:** 24 часа.

---

## Шаг 4 — vector-guided fuzzing 🔲

Применяется если шаги 1–3 не нашли SAFETY VIOLATION.
Фидбэк мутатору — не code coverage, а cosine similarity к эталонным
опасным состояниям из известных PoC (Faiss/hnswlib).

Реализация занимает ~неделю. Принимается если остальные шаги исчерпаны.

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
