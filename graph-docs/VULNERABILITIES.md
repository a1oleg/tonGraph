# Уязвимости TON Consensus — соответствие contest.com/docs/TonConsensusChallenge

Источник идей: `firstChat.md` (архив первого чата).
Скоуп контеста: баги в `validator/consensus/` (кроме `validator/consensus/null`),
а также QUIC, TwoStep broadcast и ресурсное истощение.

---

## ✅ В скоупе контеста

### 1. Equivocation (двойное голосование)

**Описание:** Byzantine валидатор подписывает два разных `NotarizeVote` за один и тот же `slot`
с разными `candidateId`.

**Инвариант:**
```
∀ v ∈ Validators, ∀ s ∈ Slots, ∀ T ∈ {notarize, finalize}:
  |{c | voted_T(v, c, s)}| ≤ 1

∀ v, s:
  voted_notarize(v, c, s) ∧ voted_skip(v, s) ⇒ ⊥

Нарушение ⇒ MisbehaviorReport(v) обязателен.
```

**Сценарий:** `ConsensusHarness --scenario equivocation`

**Детектирование (Cypher):** [CYPHER_QUERIES.md#equivocation](CYPHER_QUERIES.md#equivocation)

**Классификация контеста:** Consensus implementation bug — safety violation.

---

### 2. Liveness attack / Message withholding

**Описание:** Лидер генерирует кандидата, но не доставляет `propose` валидаторам.
Все валидаторы по таймауту шлют `SkipVote`, слот пропускается — прогресс заблокирован.

**Инвариант:**
```
∀ s ∈ Slots, L = leader(s):
  Correct(L) ⇒ ◇ Propose(L, s)           [liveness]

∀ s: alarm(s) fires ⇒ ¬voted_notar(s)    [корректность таймаута]

¬Propose(L, s) ∧ t > T_timeout ⇒
  ∀ v: SkipVote(v, s) eventually
```

**Сценарий:** `ConsensusHarness --scenario message_withholding`

**Детектирование (Cypher):** [CYPHER_QUERIES.md#withholding](CYPHER_QUERIES.md#withholding)

**Классификация контеста:** Consensus bug — liveness violation.

---

### 3. Byzantine leader / Split propose

**Описание:** Лидер шлёт разным группам валидаторов разные кандидаты (`cand_A`, `cand_B`)
за один `slot`. Ни одна группа не набирает кворум → слот пропускается.

**Инвариант:**
```
∀ L = leader(s), ∀ s ∈ Slots:
  |{c | Propose(L, c, s)}| ≤ 1

∃ c₁ ≠ c₂: Propose(L, c₁, s) ∧ Propose(L, c₂, s)
  ⇒ MisbehaviorReport(L) обязателен
```

**Сценарий:** `ConsensusHarness --scenario byzantine_leader`

**Детектирование (Cypher):** [CYPHER_QUERIES.md#byzantine-leader](CYPHER_QUERIES.md#byzantine-leader)

**Классификация контеста:** Consensus bug — safety + liveness violation.

---

### 4. State divergence

**Описание:** Два валидатора финализируют разные блоки в одном `slot` — нарушение safety.
Возникает при Byzantine quorum или ошибке в логике сертификации.

**Инвариант:**
```
∀ s ∈ Slots:
  |{c | FinalizeCert(c, s)}| ≤ 1          [safety]

FinalizeCert(c₁, s) ∧ FinalizeCert(c₂, s)
  ⇒ c₁ = c₂

SkipCert(s) ∧ FinalizeCert(c, s) ⇒ ⊥
```

**Детектирование (Cypher):** [CYPHER_QUERIES.md#dual-cert](CYPHER_QUERIES.md#dual-cert)

**Классификация контеста:** Consensus bug — critical safety violation.

---

### 5. Amnesia attack

**Описание:** Валидатор «забывает» ранее выданный `NotarizeVote` (locked кандидат)
и голосует за другой кандидат в том же `slot`. Аналог surround vote в Ethereum.

**Инвариант:**
```
∀ v ∈ Validators, ∀ s ∈ Slots, ∀ c:
  broadcast(vote(v, c, s))
    ⇒ persisted_to_db(v, c, s)            [до broadcast]

restart(v) ⇒ state(v) = load_from_db(v)

¬persisted(v, c, s) ∧ restart(v)
  ⇒ ¬voted_notarize(v, c, s) after restart
```

**Детектирование (Cypher):** [CYPHER_QUERIES.md#amnesia](CYPHER_QUERIES.md#amnesia)

**Классификация контеста:** Consensus bug — safety violation (lock bypass).

---

### 6. Message reordering

**Описание:** `NotarizeVote` доставляется до `Propose` в одном `slot`.
Если реализация не защищена от out-of-order, возможна некорректная обработка.

**Инвариант:**
```
∀ v, s:
  recv(vote, s) before recv(propose, s)
    ⇒ vote deferred or rejected          [no out-of-order accept]

bootstrap_replay(votes) with conflict(v, s)
  ⇒ MisbehaviorReport(v) обязателен

tolerate_conflicts(v) = true ⇒ log_only ≠ suppress
```

**Детектирование (Cypher):** [CYPHER_QUERIES.md#out-of-order](CYPHER_QUERIES.md#out-of-order)

**Классификация контеста:** Consensus bug — liveness / incorrect state handling.

---

### 7. Resource exhaustion — linear message flood

**Описание:** Byzantine валидатор шлёт каждому честному узлу линейное по времени число
сообщений (напр. дублированные `BroadcastVote`). Суммарно: O(N·t) сообщений → перегрузка
bandwidth (~1 Gbps на типичном железе).

**Инвариант:**
```
∀ t ∈ Time:
  |requests_| = O(|Validators|)           [bounded queue]

∀ v_byzantine, ∀ honest h:
  msgs_received(h, t) = O(1) per slot    [per-validator, per-slot]

retries(candidateId) ≤ R_max = const
```

**Проверка:** Измерить число входящих сообщений на честный узел при Byzantine отправителе
за N слотов. Должно быть O(1) на слот, не O(слоты).

**Логирование:** `MsgReceived` эмитируется в `pool.cpp handle(IncomingProtocolMessage)`
для каждого принятого vote/cert — commit [`f7be06af`](../../../commits/f7be06af).

**Детектирование (Cypher):** [CYPHER_QUERIES.md#msg-flood](CYPHER_QUERIES.md#msg-flood)

**Классификация контеста:** Resource-exhaustion bug — явно в скоупе (`linear-in-time messages`).

---

### 8. Resource exhaustion — superlinear processing

**Описание:** Byzantine актор шлёт голоса за K разных `candidateId` в одном слоте.
`notarize_weight` — `std::map<CandidateId, ValidatorWeight>` — вырастает до K записей.
Стоимость сертификации становится O(|Validators| × K) вместо O(|Validators|).
При K=100 и N=100 — 10 000 операций на сообщение, реалистичный DoS.

**Инвариант:**
```
∀ s ∈ Slots:
  |notarize_weight[s]| = O(1)             [один candidateId per slot]

cert_creation_cost(s) = O(|Validators|)

total_processing_cost(msgs)
  = O(|msgs| · |Validators|)             [линейно, не O(N²)]
```

**Логирование:** `ResourceLoad` эмитируется в `pool.cpp handle_vote` после каждого
`handle_typed_vote<NotarizeVote>` — фиксирует `notarize_weight.size()` и `requests_.size()`
per slot — commit [`f7be06af`](../../../commits/f7be06af).

**Детектирование (Cypher):** [CYPHER_QUERIES.md#notarize-weight-growth](CYPHER_QUERIES.md#notarize-weight-growth)

**Классификация контеста:** Resource-exhaustion bug (superlinear resource growth).

---

## ❌ Вне скоупа контеста

| Идея из firstChat.md | Причина исключения |
|---|---|
| Memory corruption при десериализации `td::BufferSlice` | Отклонено как «local environment attack» |
| Dead code / unreachable states в state machine | Не воспроизводимо, спекулятивно |
| Статический анализ AST через граф | Unverifiable без конкретного exploit |
| Timing attack ровно в окно `[timeout-ε, timeout+ε]` | Требует доступа к сети, вне attack model |
| Дифференциальное тестирование против LibraBFT | Результат — расхождение реализаций, не баг TON |

---

## Приоритет прогонов

```
1. [CRITICAL] State divergence         — нарушение safety, максимальный импакт
2. [HIGH]     Equivocation             — уже воспроизведён в simulation
3. [HIGH]     Byzantine leader         — уже воспроизведён в simulation
4. [HIGH]     Resource exhaustion      — linear message flood, измеримо
5. [MEDIUM]   Message withholding      — уже воспроизведён, liveness
6. [MEDIUM]   Amnesia attack           — нужна модификация сценария
7. [LOW]      Message reordering       — зависит от реализации буфера
```

---

## Лимиты воспроизведения (из условий контеста)

- Consensus bugs: **< 10 000 слотов**, **≤ 100 валидаторов**
- Resource exhaustion: должен быть реалистичный DoS на стандартном железе
- Submission: скрипт или архив + title + impact + description + reproduction
