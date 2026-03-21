# Фаззинг — Phase 1: протокольный уровень

← [Общий план](FUZZING_PLAN.md) | [Phase 2 →](FUZZING_PHASE2.md)

## Что фаззим

`fuzz_harness.cpp` фаззит **модель протокола** (ConsensusHarness-логику).
Находит баги в **дизайне протокола** — комбинации Byzantine поведений,
которые нарушают safety/liveness.

---

## Статус реализации

| Компонент | Статус |
|---|---|
| `simulation/fuzz_harness.cpp` | ✅ [54933808](https://github.com/a1oleg/tonGraph/commit/54933808) — FuzzedDataProvider (fuzzer) + FuzzReader (standalone) |
| `simulation/corpus_fuzz/` | ✅ 272 targeted seed (4 уязвимости, полное покрытие Pre(k)) |
| `simulation/scripts/gen_targeted_corpus.py` | ✅ [5aa6dab6](https://github.com/a1oleg/tonGraph/commit/5aa6dab6) — backwards reachability generator |
| `build-fuzz/simulation/fuzz_harness` | ✅ libFuzzer бинарь |
| `build-linux/simulation/fuzz_harness_standalone` | ✅ Replay с GraphLogger |

---

## ValidatorAction (6 действий)

| Action | Значение | Что делает |
|---|---|---|
| `Honest` | 0 | Голосует за полученный кандидат честно |
| `DropReceive` | 1 | Не получает кандидат → SkipVote |
| `DoubleNotarize` | 2 | Голосует за полученный + `cand_equiv` (equivocation) |
| `NotarizeAndSkip` | 3 | Notarize + Skip в одном слоте (известный баг) |
| `NoVote` | 4 | Воздерживается (тест liveness) |
| `SplitPropose` | 5 | [лидер] шлёт `cand_main` группе A, `cand_split` группе B |

---

## Инварианты в harness (в-процессные оракулы)

| Проверка | Cypher query | Тип | Триггер |
|---|---|---|---|
| Dual FinalizeCert | `#dual-cert` | SAFETY — crash | `finalize_certs[slot].size() > 1` |
| Equivocation | `#equivocation` | INVARIANT — stderr | Один валидатор → два notarize cand |
| Notarize+Skip | `#notarize-skip` | INVARIANT — stderr | Один валидатор → notarize + skip |
| Duplicate proposal | `#candidate-duplicate` | INVARIANT — stderr | Лидер → 2 разных candidateId |
| NotarizeCert+SkipCert | — | INVARIANT — stderr | Оба сертификата на одном слоте |
| No finalized blocks | `#liveness` | INVARIANT — stderr | 0 финализировано и не всё skipped |
| alarm-skip-after-notarize | `#alarm-skip-after-notarize` | — | Требует alarm() — Phase 2 |
| Amnesia gap | `#amnesia-gap` | — | Требует WAL crash — Phase 2 |

---

## gen_targeted_corpus.py — 272 файла

Backwards reachability: каждая уязвимость → Pre(k) каскад → аналитически конечное множество inputs.

| Генератор | Файлов | Покрытие |
|---|---|---|
| `gen_dual_cert_pressure` | 130 | Все разбиения с хотя бы одной группой ≥ threshold−1 |
| `gen_equivocation_pressure` | 88 | DoubleNotarize на каждой позиции + пары Byzantine |
| `gen_notarize_skip_pressure` | 18 | NotarizeAndSkip на каждой позиции |
| `gen_liveness_pressure` | 36 | Leader drop + threshold−1 no-vote |

```python
# ∃ partition(validators) : |A| >= threshold AND |B| >= threshold
# AND leader sends cand_0 to A, cand_1 to B
for N in range(3, 7):
    threshold = N - 1
    for split in combinations_with_threshold(N, threshold):
        emit_corpus_file(N, split)
```

---

## Регламент прогонов

Corpus **накапливается** — не чистить без причины:

```bash
mkdir -p simulation/corpus_fuzz_run simulation/crashes

REPO=$(pwd)
tmux new-session -d -s fuzz \
  "./build-fuzz/simulation/fuzz_harness \
  $REPO/simulation/corpus_fuzz_run/ \
  $REPO/simulation/corpus_fuzz/ \
  -max_total_time=86400 -jobs=$(nproc) \
  -artifact_prefix=$REPO/simulation/crashes/ \
  >> $REPO/simulation/fuzz.log 2>&1"
```

Чистить corpus только если изменился код harness (изменился enum `ValidatorAction`).
После изменения — перегенерировать: `python3 simulation/scripts/gen_targeted_corpus.py`
Минимизация: `./fuzz_harness -merge=1 corpus_min/ corpus_fuzz_run/`

---

## Workflow при находке краша

```bash
# 1. libFuzzer сохранил crash:
#    simulation/crashes/crash-<hash>

# 2. Replay с трассой:
GRAPH_LOGGING_ENABLED=1 \
GRAPH_LOG_FILE=$(pwd)/simulation/trace.ndjson \
  ./build-linux/simulation/fuzz_harness_standalone \
  simulation/crashes/crash-<hash>

# 3. Отправить в Neo4j:
cd simulation && node relay.mjs --clear trace.ndjson

# 4. Запросить аномалии:
node query.mjs <sessionId>
```

---

## Результаты прогона (2026-03-19)

| Параметр | Значение |
|---|---|
| Длительность | ~12 часов (остановлен досрочно — coverage plateau) |
| Итерации (воркер 0) | ~239M |
| Скорость | ~6570 iter/sec |
| Воркеров | 16–20 (nproc) |
| Coverage | `cov: 913 ft: 5116` — плато с первых часов |
| Corpus | 6064 файлов (вырос с 272 → 3343 → 5244 → 6064) |
| **SAFETY VIOLATION** (`#dual-cert`) | **0** — не найден |
| INVARIANT VIOLATION | Найдены (equivocation, duplicate proposal, notarize+skip) — ожидаемо |
| Crashes | 0 |

**Вывод:** Coverage вышла на плато `cov: 913` — все достижимые ветки покрыты. `#dual-cert` в модели при N=3..6 не воспроизводится.

Возможные причины:
- Протокол корректен на уровне модели при данных предположениях
- Harness не моделирует часть условий для dual-cert (сетевые задержки, WAL crash)
- Требуется Phase 2 с реальным `pool.cpp`

---

## Уроки и улучшения

**Plateau detection.** libFuzzer не умеет останавливаться при plateau автоматически.
В следующих прогонах добавить в `fuzz_watch.sh` детектор — мониторить `ft:` в логе,
останавливать если не растёт >1 часа:

```bash
last_ft=0; last_change=$(date +%s)
while true; do
  ft=$(grep -o 'ft: [0-9]*' fuzz-0.log | tail -1 | awk '{print $2}')
  if [ "$ft" != "$last_ft" ]; then last_ft=$ft; last_change=$(date +%s)
  else
    stale=$(( $(date +%s) - last_change ))
    if [ $stale -gt 3600 ]; then echo "plateau ${stale}s, stopping"; pkill -f fuzz_harness; break; fi
  fi
  sleep 60
done
```

**Лог-спам.** `[fuzz] INVARIANT VIOLATION` печаталось на каждой итерации → 80GB логов за 12 часов.
Исправлено: вывод убран из harness, остался только SAFETY VIOLATION перед `__builtin_trap()`.
