# Фаззинг simplex consensus — общий план

## Два уровня

| | Phase 1 | Phase 2 |
|---|---|---|
| Что фаззим | Модель протокола (ConsensusHarness) | Реализацию (`pool.cpp`) |
| Находит | Баги в дизайне протокола | Баги в реализации (TL, WAL, overflow) |
| Скорость | ~6500 iter/sec | ~100–1000 iter/sec (ожидаемо) |
| Статус | ✅ Реализовано, прогон завершён | 🔲 Будущая работа |
| Подробнее | [FUZZING_PHASE1.md](FUZZING_PHASE1.md) | [FUZZING_PHASE2.md](FUZZING_PHASE2.md) |

---

## Оптимальный порядок (применимо к обеим фазам)

```
Шаг 1: FuzzedDataProvider           → структурная валидность
        +
        gen_targeted_corpus.py       → стартуем в опасной зоне
        ↓
        Corpus прогрет и структурирован

Шаг 2: Properties as assertions      → убираем Neo4j из inner loop
        +
        Dictionary                   → граничные значения
        ↓
        Прямые crashes без round-trip

Шаг 3: (если crashes не найдены за 24ч)
        Corpus из testnet             → реальные паттерны
        +
        AFL++ grammar                 → мутации на уровне протокола

Шаг 4: (для найденных crashes)
        Replay с GraphLogger          → trace.ndjson
        relay.mjs → Neo4j             → Cypher-запросы
        → понять что именно нарушено и почему
```

**Шаги 1+2** дают 80% выхлопа за 20% усилий.
**Шаги 3+4** нужны если 1+2 за 24 часа не нашли `SAFETY VIOLATION`.

---

## Стратегии мутации: снаружи внутрь

```
Пространство: ~256^N
      ▼  [FuzzedDataProvider]   — структурная валидность
      ▼  [Dictionary]           — граничные значения
      ▼  [Corpus из testnet]    — реальные паттерны
      ▼  [AFL++ grammar]        — мутации на уровне протокола
      ▼
  Интересные inputs → Neo4j → Cypher → аномалии
```

Corpus для fuzzer берётся из:
- Перехваченных реальных сообщений с testnet (через ADNL-трейс)
- Сгенерированных мутаций из существующих unit-тестов

---

## Стратегии мутации: обратная достижимость (backwards reachability)

Уязвимость — конечная точка каскада состояний. Идём **назад от нарушения**,
вычисляя предусловия (wp-исчисление Дейкстры):

```
VIOLATION: finalize_certs[slot].size() > 1
  ← Pre-1: два кандидата набрали finalize_weight >= threshold
    ← Pre-2: два кандидата набрали notarize_weight >= threshold
      ← Pre-3: Byzantine валидатор голосует за оба +
               две группы ≥ threshold получили разные candidateId
        ← Input: {SplitPropose лидер, partition(validators, A≥thr, B≥thr)}
```

- **Phase 1:** пространство аналитически конечно → `gen_targeted_corpus.py` решает явно
- **Phase 2:** пространство ~2^64 → vector-guided fuzzing (Faiss/hnswlib)

---

## Ограничения

- **Масштаб**: consensus fuzzing генерирует миллионы событий — batch-optimized pipeline обязателен (batch size 500 в `flushLoop` — хороший старт)
- **Детерминизм**: для воспроизведения бага логировать seed рандома и порядок сообщений

---

## Следующие шаги

1. ~~**`FuzzedDataProvider`**~~ — ✅ [54933808](https://github.com/a1oleg/tonGraph/commit/54933808)
2. ~~**Properties as assertions**~~ — ✅ [0f729a39](https://github.com/a1oleg/tonGraph/commit/0f729a39)
3. ~~**Phase 1 прогон**~~ — ✅ 2026-03-19, ~239M итераций, SAFETY VIOLATION не найден → [результаты](FUZZING_PHASE1.md#результаты-прогона-2026-03-19)
4. **Phase 2** — [FUZZING_PHASE2.md](FUZZING_PHASE2.md)
