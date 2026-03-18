#!/usr/bin/env python3
"""Generate targeted corpus files for fuzz_harness based on backwards reachability.

For each vulnerability, computes Pre(k) — the set of inputs that can lead to the
anomaly — and generates corpus files that start the fuzzer directly in the
dangerous zone rather than searching for it from scratch.

Output: simulation/corpus_fuzz/<name> binary files for libFuzzer corpus.

Vulnerabilities covered:
  #dual-cert     — SplitPropose: Byzantine leader splits validator groups
  #equivocation  — DoubleNotarize at each validator position
  #notarize-skip — NotarizeAndSkip at each validator position
  #liveness      — DropReceive / NoVote for leader + quorum
"""

import itertools
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(SCRIPT_DIR, '..', 'corpus_fuzz')

MIN_VALIDATORS = 3
MAX_VALIDATORS = 6
MAX_BYZ        = 1   # f=1, threshold = N - 1

# Must match ValidatorAction enum in fuzz_harness.cpp
HONEST          = 0
DROP_RECEIVE    = 1
DOUBLE_NOTARIZE = 2
NOTARIZE_SKIP   = 3
NO_VOTE         = 4
SPLIT_PROPOSE   = 5


def encode_session(n: int, slots: list[list]) -> bytes:
    """Encode a session as fuzz_harness input bytes.

    Byte layout:
      [0] n_validators offset: harness reads MIN + rdr.next(MAX-MIN+1) = MIN + (byte % 4)
      [1] n_slots offset:      harness reads 1 + rdr.next(MAX_SLOTS=15) = 1 + (byte % 15)
      For each slot s:
        actions[0..N-1]: one byte per validator
        If leader's action == SPLIT_PROPOSE:
          partition[0..N-2]: one bool byte per non-leader validator
                             0 → group A (cand_main), 1 → group B (cand_split)
    """
    data = bytearray()
    data.append(n - MIN_VALIDATORS)            # 0..3 → N in [3,6]
    data.append(max(0, len(slots) - 1))        # 0..14 → n_slots in [1,15]
    for s, slot in enumerate(slots):
        leader = s % n
        actions = slot['actions']
        partition = slot.get('partition', None)
        for a in actions:
            data.append(a)
        if actions[leader] == SPLIT_PROPOSE:
            if partition is None:
                # Default: alternate groups
                non_leaders = [v for v in range(n) if v != leader]
                partition = [i % 2 for i in range(len(non_leaders))]
            for p in partition:
                data.append(1 if p else 0)
    return bytes(data)


def honest_slot(n: int) -> dict:
    return {'actions': [HONEST] * n}


# ── #dual-cert: SplitPropose ──────────────────────────────────────────────────
# Backwards reachability:
#   VIOLATION: finalize_certs[slot].size() > 1
#   ← Pre-1: two candidates reach finalize quorum (finalize_w >= threshold each)
#   ← Pre-2: two candidates reach notarize quorum (notarize_w >= threshold each)
#   ← Pre-3: Byzantine leader partitions validators; each group >= threshold
#   ← Input: SplitPropose + partition(A >= threshold, B >= threshold)
#
# With f=1 (threshold = N-1), any split of N-1 non-leader validators gives
# max group size = N-1. For dual quorum: |A| >= N-1 AND |B| >= N-1, which
# requires N-1 + N-1 <= N-1 → impossible without overlap.
# Therefore: this generates interesting graph patterns (CandidateDuplicate)
# but safety should hold. If a bug exists in check_invariants, it will fire.

def gen_dual_cert_pressure():
    for n in range(MIN_VALIDATORS, MAX_VALIDATORS + 1):
        threshold = n - MAX_BYZ
        non_leader_count = n - 1  # leader is the Byzantine one

        # Enumerate all partitions of non-leader validators into two groups
        for leader_pos in range(n):
            non_leaders = [v for v in range(n) if v != leader_pos]
            # k = size of group A
            for k in range(1, len(non_leaders)):
                group_b_size = len(non_leaders) - k
                # Only generate partitions where at least one group is close to threshold
                if k < threshold - 1 and group_b_size < threshold - 1:
                    continue
                for group_a_idx in itertools.combinations(range(len(non_leaders)), k):
                    group_a_set = set(group_a_idx)
                    partition = [0 if i in group_a_set else 1
                                 for i in range(len(non_leaders))]
                    # Build a session: the target slot uses leader_pos as leader,
                    # surrounded by honest slots for context
                    n_slots = max(3, leader_pos + 1)
                    slots = []
                    for s in range(n_slots):
                        actual_leader = s % n
                        if actual_leader == leader_pos:
                            slots.append({
                                'actions': [SPLIT_PROPOSE if v == leader_pos else HONEST
                                            for v in range(n)],
                                'partition': partition,
                            })
                        else:
                            slots.append(honest_slot(n))
                    name = (f"dual_cert_n{n}_l{leader_pos}"
                            f"_A{k}_B{group_b_size}"
                            f"_p{''.join(str(p) for p in partition)}")
                    yield name, encode_session(n, slots)


# ── #equivocation: DoubleNotarize ─────────────────────────────────────────────
# Backwards reachability:
#   VIOLATION: votes_by_slot[slot][v] contains two different notarize candidateIds
#   ← Pre-1: validator v emits NotarizeVote for two different candidates
#   ← Input: actions[v] == DoubleNotarize, v receives some candidate

def gen_equivocation_pressure():
    for n in range(MIN_VALIDATORS, MAX_VALIDATORS + 1):
        # Byzantine validator at each position
        for byz_v in range(n):
            for n_slots in [3, 5, 8]:
                slots = []
                for s in range(n_slots):
                    actions = [HONEST] * n
                    actions[byz_v] = DOUBLE_NOTARIZE
                    slots.append({'actions': actions})
                yield (f"equiv_n{n}_byz{byz_v}_s{n_slots}",
                       encode_session(n, slots))

        # Two Byzantine validators simultaneously (stress test, allowed since MAX_BYZ=1 model)
        for byz_a, byz_b in itertools.combinations(range(n), 2):
            actions = [HONEST] * n
            actions[byz_a] = DOUBLE_NOTARIZE
            actions[byz_b] = DOUBLE_NOTARIZE
            slots = [{'actions': actions}] * 3
            yield (f"equiv_n{n}_2byz_{byz_a}_{byz_b}",
                   encode_session(n, slots))


# ── #notarize-skip: NotarizeAndSkip ───────────────────────────────────────────
# Backwards reachability:
#   VIOLATION: votes_by_slot[slot][v] has both notarize and skip
#   ← Input: actions[v] == NotarizeAndSkip

def gen_notarize_skip_pressure():
    for n in range(MIN_VALIDATORS, MAX_VALIDATORS + 1):
        for byz_v in range(n):
            slots = []
            for s in range(4):
                actions = [HONEST] * n
                actions[byz_v] = NOTARIZE_SKIP
                slots.append({'actions': actions})
            yield (f"notar_skip_n{n}_byz{byz_v}",
                   encode_session(n, slots))


# ── #liveness: message withholding ────────────────────────────────────────────
# Leader drops propose; quorum of other validators no-votes → no progress.

def gen_liveness_pressure():
    for n in range(MIN_VALIDATORS, MAX_VALIDATORS + 1):
        threshold = n - MAX_BYZ
        for leader_slot_idx in range(n):
            # Scenario 1: leader drops
            n_slots = n  # enough to exercise each validator as leader
            slots = []
            for s in range(n_slots):
                actual_leader = s % n
                actions = [HONEST] * n
                if actual_leader == leader_slot_idx:
                    actions[actual_leader] = DROP_RECEIVE
                slots.append({'actions': actions})
            yield (f"liveness_drop_n{n}_l{leader_slot_idx}",
                   encode_session(n, slots))

            # Scenario 2: leader drops + f validators no-vote → exactly threshold-1 votes
            slots2 = []
            for s in range(n_slots):
                actual_leader = s % n
                actions = [HONEST] * n
                if actual_leader == leader_slot_idx:
                    actions[actual_leader] = DROP_RECEIVE
                    # Make threshold-1 other validators also abstain
                    others = [v for v in range(n) if v != actual_leader]
                    for v in others[:threshold - 1]:
                        actions[v] = NO_VOTE
                slots2.append({'actions': actions})
            yield (f"liveness_drop_novote_n{n}_l{leader_slot_idx}",
                   encode_session(n, slots2))


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    count = 0

    generators = [
        ("dual_cert",       gen_dual_cert_pressure()),
        ("equivocation",    gen_equivocation_pressure()),
        ("notarize_skip",   gen_notarize_skip_pressure()),
        ("liveness",        gen_liveness_pressure()),
    ]

    counts = {}
    for label, gen in generators:
        n = 0
        for name, data in gen:
            path = os.path.join(OUTPUT_DIR, name)
            with open(path, 'wb') as f:
                f.write(data)
            n += 1
            count += 1
        counts[label] = n
        print(f"  {label}: {n} files")

    print(f"Total: {count} targeted corpus files → {OUTPUT_DIR}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
