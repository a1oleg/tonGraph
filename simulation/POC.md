# Proof-of-Concept: SimplexConsensus pool.cpp — три подтверждённых уязвимости

Все три PoC — минимальные бинарные inputs для `build-fuzz2/test/consensus/fuzz_pool`.
Каждый воспроизводится детерминированно и вызывает `__builtin_trap()` (SIGTRAP, exit 77).

```
BINARY=./build-fuzz2/test/consensus/fuzz_pool
$BINARY simulation/poc_msg_flood.bin    # → pool.cpp:430 (#msg-flood)
$BINARY simulation/poc_req_flood.bin    # → pool.cpp:516 (#request-no-bound)
$BINARY simulation/poc_cand_growth.bin  # → pool.cpp:674 (#candidate-map-growth)
```

---

## PoC 1 — #msg-flood (pool.cpp:430)

**Файл:** `simulation/poc_msg_flood.bin` (24 байта)

### Атака
Злонамеренный peer шлёт более 4 идентичных голосов (один тип, один слот) от одного источника.

```
src=val1, vote=NotarizeVote{slot=0, cand=hash_0}  ×5
```

### Путь в коде
```
IncomingProtocolMessage → pool.cpp:391 fetch_tl_object<tl::vote>
  → handle_vote(validator, Signed<Vote>)
  → msg_flood_counter_[{source.value(), slot}]++  (pool.cpp:428)
  → counter > kMsgFloodThreshold(4) → __builtin_trap()  (pool.cpp:430)
```

### Инвариант
Честный валидатор отправляет O(1) сообщений одного типа на (slot, source).
Более 4 — Byzantine flooding.

### Воздействие
**DoS нода**: без rate-limit pool принимает неограниченное число одинаковых
сообщений. Злоумышленник может заставить ноду обработать N сообщений за
O(N) вместо O(1), удваивая нагрузку при N=5 и делая её произвольной при N→∞.

---

## PoC 2 — #request-no-bound (pool.cpp:516)

**Файл:** `simulation/poc_req_flood.bin` (20 байт)

### Атака
Злонамеренный лидер публикует 4+ candidate-proposals с непрезолвленным
parent-слотом. Каждый создаёт подвешенный `WaitForParent` в очереди `requests_`.

```
CandidateReceived{slot=1, parent=slot0}  (slot 0 not notarized → pending)
CandidateReceived{slot=2, parent=slot1}  (slot 1 not notarized → pending)
CandidateReceived{slot=3, parent=slot2}  (slot 2 not notarized → pending)
CandidateReceived{slot=4, parent=slot3}  (slot 3 not notarized → pending)
→ requests_.size() = 4 ≥ kRequestsFloodThreshold(4) → __builtin_trap()
```

### Путь в коде
```
CandidateReceived → ConsensusImpl::handle_candidate_received
  → try_notarize → WaitForParent published
  → pool.cpp:process(WaitForParent)
  → requests_.push_back(...)  (без проверки размера)
  → requests_.size() >= 4 → __builtin_trap()  (pool.cpp:516)
```

### Инвариант
`|requests_|` должна быть O(|Validators|) — ограниченная очередь.
Злонамеренный лидер может создать произвольно длинную очередь, вызывая
O(|requests_|) итерацию в `maybe_resolve_requests()` при каждом обновлении слота.

### Воздействие
**Суперлинейная нагрузка**: `maybe_resolve_requests()` итерирует весь вектор
при каждом нотаризованном слоте. При K накопленных requests и S слотах:
O(K × S) работы вместо O(S). Byzantine leader с K=100 увеличивает нагрузку в 100×.

---

## PoC 3 — #candidate-map-growth (pool.cpp:674)

**Файл:** `simulation/poc_cand_growth.bin` (16 байт)

### Атака
3 validator-а (или один Byzantine validator) отправляют NotarizeVote за
разные candidateId на одном слоте. `notarize_weight` растёт до 3 записей.

```
val0: NotarizeVote{slot=0, hash=cand_hashes[0]}
val1: NotarizeVote{slot=0, hash=cand_hashes[1]}
val2: NotarizeVote{slot=0, hash=cand_hashes[2]}
→ notarize_weight[slot0].size() = 3 ≥ 3 → __builtin_trap()
```

### Путь в коде
```
IncomingProtocolMessage → handle_vote → handle_typed_vote<NotarizeVote>
  → notarize_weight[vote.vote.id] += validator.weight  (per CandidateId)
  → notarize_weight.size() >= 3 → __builtin_trap()  (pool.cpp:674)
```

### Инвариант
Честный лидер предлагает ровно 1 candidateId на слот.
≥3 различных candidateId = Byzantine flooding с разными хешами.

### Воздействие
**Суперлинейная стоимость cert-creation**: cert_creation_cost = O(|Validators| × K),
где K = число distinct candidateId. При K=100, N=100 validators:
10 000 операций вместо 100 на каждое входящее сообщение.

---

## Структура PoC-файлов

FuzzedDataProvider читает control-байты **с конца** буфера. Формат (читается справа налево):

```
[msg_data...] [msg_N.cand] [msg_N.slot] [msg_N.vtype] [msg_N.src] ... [n_post] [n_lose] [do_crash] [n_pre]
              ← конец буфера (читается первым)
```

Типы событий (vote_type, 0..6): 0=NotarizeVote, 1=SkipVote, 2=FinalizeVote,
3=CandidateReceived, 4=RawIncomingProtocolMessage, 5=BroadcastVote, 6=IncomingOverlayRequest.
