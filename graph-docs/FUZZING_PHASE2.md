# Фаззинг — Phase 2: уровень реализации

[← Phase 1](FUZZING_PHASE1.md) | [Общий план](FUZZING_PLAN.md)

## Что фаззим

Реальный `pool.cpp` через mock actor runtime.
Находит баги в **реализации** — TL-десериализация, integer overflow, use-after-free,
WAL-состояния, race conditions при доставке сообщений.

В отличие от Phase 1 (модель, N≤6), здесь пространство состояний ~2^64.

---

## Статус

🔲 Не реализовано. Требует ~500 строк scaffolding.

---

## Scaffolding (что нужно написать)

```cpp
// MockBus — детерминированная доставка сообщений
struct MockBus {
    void send(ActorId to, Message msg);
    void deliver_next();          // управляемая доставка
    void drop_next();             // симуляция потери пакета
    void reorder(int i, int j);   // перестановка очереди
};

// MockKeyring — подписи без криптографии
struct MockKeyring {
    Signature sign(PublicKey key, Bytes data);  // детерминированно
};

// MockDb — WAL без диска
struct MockDb {
    void write(Key, Value);
    void crash_and_recover();  // симуляция краша + восстановления
};
```

---

## Стратегии мутации

### 1. Снаружи внутрь (структурная валидность)

```
Пространство: ~256^N (все байт-последовательности)
      │
      ▼  [FuzzedDataProvider]
      │  Структурная валидность TL-сообщений
      │  Сужение: ~10^9×
      │
      ▼  [Dictionary]
      │  TL-теги, magic bytes, граничные значения
      │
      ▼  [Corpus из testnet]
         Реальные trace.ndjson → corpus-файлы
```

### 2. Backwards reachability (vector-guided)

Для `pool.cpp` аналитическое Pre(k) нереально — пространство слишком большое.
Вместо этого: **vector-guided fuzzing**.

```
snapshot C++ состояния (notarize_weight map, requests_ queue, voted_notar flags)
    → кодируем в числовой вектор
    → Faiss/hnswlib хранит "эталонные опасные состояния" из известных PoC
    → при фаззинге: cosine similarity к ближайшему опасному состоянию
    → это фидбэк мутатору (вместо code coverage)
```

Мутатор делает шаг в сторону **уменьшения расстояния до нарушения**,
не в сторону случайного покрытия новых базовых блоков.

### 3. Coverage-directed к аномалиям

```
libFuzzer генерирует сценарий
    → pool.cpp запускается с MockBus/MockKeyring/MockDb
    → вычисляет "расстояние" до нарушения свойства
      (например: max(notarize_weight) - threshold для #dual-cert)
    → возвращает сигнал мутатору через LLVMFuzzerCustomMutator
    → мутатор делает шаг в сторону уменьшения расстояния
```

### 4. WAL crash injection

```cpp
// В LLVMFuzzerTestOneInput:
bool inject_crash = fdp.ConsumeBool();
if (inject_crash) db.crash_and_recover();
// → тестирует #amnesia-gap и #alarm-skip-after-notarize
```

---

## Инварианты для Phase 2

| Проверка | Cypher query | Как проверять |
|---|---|---|
| alarm-skip-after-notarize | `#alarm-skip-after-notarize` | После WAL recover: если votedNotar=true и пришёл AlarmSkip → crash |
| Amnesia gap | `#amnesia-gap` | VoteIntentSet записан, но WAL crash → после recover vote_intent отсутствует |

Оба требуют `MockDb::crash_and_recover()` — недоступно в Phase 1.

---

## Управление plateau

В Phase 2 plateau означает принципиально другое, чем в Phase 1:

| Сигнал | Значение | Реакция |
|---|---|---|
| `ft:` не растёт >1h | Мутатор застрял в локальном минимуме | Merge corpus + новые targeted seeds |
| `ft:` растёт медленно | Исследуем глубокий код | Нормально, продолжать |
| Distance-to-violation не уменьшается | Не приближаемся к нарушению | Сменить seed или стратегию мутации |

**Не останавливать при plateau — перезапускать с новой стратегией:**

```bash
# При обнаружении plateau (ft не растёт >1h):
# 1. Минимизировать corpus
./build-fuzz/simulation/fuzz_harness2 -merge=1 corpus_min/ corpus_fuzz_run/
# 2. Догенерировать targeted seeds из текущих "ближайших" состояний
python3 scripts/gen_targeted_corpus_phase2.py --from-closest
# 3. Перезапустить с обновлённым corpus
```

**Corpus bloat.** `pool.cpp` генерирует намного больше интересных путей, чем модель.
Corpus может раздуться до десятков тысяч файлов. Периодический merge в `fuzz_watch.sh` — каждые 4 часа:

```bash
# в fuzz_watch.sh
if [ $(( $(date +%s) % 14400 )) -lt 10 ]; then
  ./build-fuzz/.../fuzz_harness2 -merge=1 \
    "$REPO/simulation/corpus_fuzz_run2_min/" \
    "$REPO/simulation/corpus_fuzz_run2/"
fi
```

---

## Порядок реализации

1. MockBus + MockKeyring + MockDb scaffolding
2. `fuzz_harness2.cpp` — `LLVMFuzzerTestOneInput` вызывает `pool.cpp`
3. Corpus из testnet: `trace.ndjson` → `trace_to_corpus_phase2.py`
4. WAL crash injection
5. Vector-guided fuzzing (опционально, если 1–4 не дали результата)
