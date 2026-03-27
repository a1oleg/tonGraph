/*
 * Copyright (c) 2025-2026, TON CORE TECHNOLOGIES CO. L.L.C
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 *
 * Phase 2 Steps 2–4 + Phase 3 Steps 2–3 + Phase 4 Step 0 fuzzer: pool.cpp + ConsensusImpl.
 *
 * Step 2: vote-accumulation, cert-creation, WAL (MockDb) paths.
 * Step 3: WAL crash injection (MockDb::crash_losing_last_n + restart).
 * Step 4: state-vector counters for semantic coverage guidance.
 * Phase 3 Step 2: ConsensusImpl registered, enabling alarm-skip-after-notarize
 *   detection via the start_up() SkipVote broadcast path.
 *   FuzzStubResolver handles ResolveState / ResolveCandidate with error returns
 *   so detached coroutines in start_generation() abort gracefully.
 *   SkipCerts detected in OutgoingProtocolMessage → cross-boundary
 *   dual-cert (NotarCert + SkipCert) triggers __builtin_trap().
 *
 * Ed25519 signature verification is bypassed via
 * PeerValidator::g_skip_signature_check.  MockKeyring returns dummy
 * 64-byte signatures so bootstrap_votes can be re-signed after crash.
 *
 * Fuzz input layout (FuzzedDataProvider — all fields consumed from back of buffer):
 *   n_pre        : uint8  (0..15)  — messages before crash
 *   do_perm      : bool            — shuffle pre-crash messages (Fisher-Yates)
 *   perm_seed    : uint8           — LCG seed for permutation (consumed only if do_perm)
 *   n_crashes    : uint8  (0..2)   — number of sequential crash+restart cycles
 *   n_mid_ticks  : uint8  (0..2)   — alarm ticks fired between pre-msgs and crash loop
 *   n_post       : uint8  (0..7)   — messages after last crash
 *   do_perm_post : bool            — shuffle post-crash messages (Fisher-Yates)
 *   perm_post_seed : uint8         — LCG seed for post permutation (only if do_perm_post)
 *   n_ticks      : uint8  (0..3)   — times to fire standstill alarm (run(15.0))
 *   n_post_tick  : uint8  (0..4)   — messages after all ticks (post-alarm injection)
 *   per message:
 *     src_idx   : uint8  (1..N_VALIDATORS-1)
 *     vote_type : uint8  (0=notarize, 1=skip, 2=finalize, 3=propose/CandidateReceived,
 *                          4=raw/IncomingProtocolMessage, 5=BroadcastVote/handle_our_vote,
 *                          6=IncomingOverlayRequest/CandidateResolver,
 *                          7=NotarizationObserved/ConsensusImpl::try_vote_final,
 *                          8=FinalizationObserved/direct FinalCert inject,
 *                          9=threshold-burst split: injects threshold-1 NotarizeVotes for
 *                            cand_seed then 1 NotarizeVote for (cand_seed+1)%N_CAND_SEEDS,
 *                         10=SkipVote flood: injects threshold SkipVotes → deterministic SkipCert,
 *                         11=multi-slot chain: sub-threshold NotarVotes[s] + 1 SkipVote[s+1]
 *                            + 1 NotarVote[s+2]; tests cross-slot state interactions,
 *                         12=FinalizeVote flood: injects threshold FinalizeVotes → FinalCert,
 *                         13=Byzantine double-vote: same validator casts NotarizeVote+SkipVote,
 *                         14=LeaderWindowObserved inject: direct window-advance event,
 *                         15=window-spanning skip: SkipVote flood for all slots in window
 *                            containing slot → forces LeaderWindowObserved naturally)
 *     slot      : uint8  (0..MAX_SLOT)
 *     cand_seed : uint8  (0..N_CAND_SEEDS-1)
 *   n_windows       : uint8  (0..2)   — complete windows to skip before crash loop
 *   per crash (consumed inside crash loop):
 *     n_lose_i        : uint8  (0..MAX_LOSE_WRITES)
 *     lose_mode       : uint8  (0..4) — 0=last N, 1=first N, 2..4=stride
 *     n_inter_i       : uint8  (0..4) — inter-crash messages
 *     n_inter_ticks_i : uint8  (0..2) — alarm ticks after inter-crash messages
 *   n_post_crashes  : uint8  (0..1)   — extra crash after post-msgs (before n_ticks)
 *   per post-crash: n_lose_pc, lose_mode_pc(0..4)
 *
 * Permutation: when do_perm=true, all n_pre messages are read upfront and shuffled
 * via Fisher-Yates before injection. Tests order-dependent state bugs, including
 * ConflictTolerated during bootstrap replay (#conflict-tolerated detector).
 *
 * Build (FUZZING=ON cmake build):
 *   cmake --build build-fuzz2 --target fuzz_pool -- -j$(nproc)
 *
 * Test run (1 hour):
 *   REPO=$(pwd)
 *   mkdir -p simulation/corpus_fuzz_pool simulation/crashes_pool
 *   tmux new-session -d -s fuzz_pool \
 *     "cd $REPO && timeout 3600 ./build-fuzz2/test/consensus/fuzz_pool \
 *      $REPO/simulation/corpus_fuzz_pool/ \
 *      -max_total_time=3600 -jobs=$(nproc) \
 *      -artifact_prefix=$REPO/simulation/crashes_pool/ \
 *      >> $REPO/simulation/fuzz_pool.log 2>&1"
 */

#include <fuzzer/FuzzedDataProvider.h>
#include <cstring>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "auto/tl/ton_api.h"
#include "auto/tl/ton_api.hpp"
#include "consensus/simplex/bus.h"
#include "consensus/bus.h"
#include "consensus/types.h"
#include "keyring/keyring.h"
#include "keys/keys.hpp"
#include "td/actor/BusRuntime.h"
#include "td/actor/actor.h"
#include "td/actor/common.h"
#include "td/actor/core/SchedulerContext.h"
#include "td/actor/coro_utils.h"
#include "tl-utils/common-utils.hpp"
#include "ton/ton-types.h"
#include "validator/interfaces/validator-manager.h"

#include "consensus/chain-state.h"
#include "crypto/vm/boc.h"
#include "crypto/vm/cells.h"
#include "simulation/GraphLogger.h"
#include "td/utils/logging.h"

#include <cmath>

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
// Defined in validator/consensus/simplex/pool.cpp.
// Tracks number of WaitForParent requests currently pending in PoolImpl::requests_.
// Used by crash_and_restart to drain until all coroutine promises are resolved.
// g_conflict_tolerated_count: incremented each time ConflictTolerated fires during
// bootstrap replay (tolerate_conflicts=true). Nonzero after crash_and_restart means
// the local validator had conflicting votes in DB — safety violation (#conflict-tolerated).
namespace ton::validator::consensus::simplex {
extern std::atomic<int> g_pending_requests_count;
extern std::atomic<int> g_conflict_tolerated_count;
}
#endif

// ─────────────────────────────────────────────────────────────────────────────

#ifndef N_VALIDATORS_OVERRIDE
static constexpr size_t N_VALIDATORS = 4;
#else
static constexpr size_t N_VALIDATORS = N_VALIDATORS_OVERRIDE;
#endif
static constexpr uint8_t MAX_SLOT = 15;
static constexpr size_t  SLOTS_PER_WINDOW  = 4;  // must match simplex_config.slots_per_leader_window
static constexpr size_t  WEIGHT_THRESHOLD  = (N_VALIDATORS * 2) / 3 + 1;
static constexpr uint8_t N_CAND_SEEDS = 4;
static constexpr uint8_t MAX_LOSE_WRITES = 8;
static constexpr int DRAIN_ROUNDS = 20;
static constexpr int DRAIN_CRASH_ROUNDS = 200;
// Extra scheduler rounds run AFTER g_pending_requests_count hits 0 to let
// all WaitForParent coroutine continuations fully unwind before runtime.reset().
static constexpr int EXTRA_DRAIN_AFTER_TEARDOWN = 20;

// ── Step 4: State-vector counters ─────────────────────────────────────────────
//
// 16 slots × 8 events = 128 bytes of per-slot counters, plus 8 global bytes.
// Registered with libFuzzer via __sanitizer_cov_8bit_counters_init so the
// fuzzer treats new semantic state-combinations as new "coverage" even after
// code-coverage has plateaued.
//
// Per-slot events (index = slot * 8 + event):
//   0  NOTAR_VOTE  — our notarize vote was broadcast for this slot
//   1  SKIP_VOTE   — a skip vote was broadcast for this slot
//   2  FINAL_VOTE  — a finalize vote was broadcast for this slot
//   3  NOTAR_CERT  — notarize cert observed for this slot
//   4  POST_CRASH  — any vote/cert event for this slot after crash+restart
//   5  BOTH_NS     — DANGER: both notarize AND skip votes on same slot
//   6  CERT_SKIP   — DANGER: notarize cert + skip votes on same slot
//   7  reserved
//
// Global counters at offset 128:
//   128  CRASHED          — crash+restart happened this run
//   129  WINDOW_ADVANCED  — LeaderWindowObserved fired (window progressed)
//   130  POST_CRASH_CERT  — notarize cert observed after crash (safety stress)
//   131  LIVENESS_MISS    — n_ticks>0 + windows advanced but zero certs issued this run
//   132  MULTI_CRASHED    — n_crashes > 1 this run (WAL accumulation across restarts)
//   133  POST_TICK_MSG    — message injected after alarm tick (post-alarm state probe)
//   134  THRESHOLD_SPLIT  — vtype=9 injected (notarize_weight split below quorum)

static constexpr int STATE_COUNTER_BYTES = 149;
static constexpr int SE_STRIDE = 8;
static uint8_t g_state_counters[STATE_COUNTER_BYTES] = {};

// __sanitizer_cov_trace_cmp1 is part of the libFuzzer/SanitizerCoverage ABI.
// With -use_value_profile=1 each unique (arg1,arg2) pair counts as new
// coverage.  We use it to signal dangerous state combinations to libFuzzer.
extern "C" void __sanitizer_cov_trace_cmp1(uint8_t arg1, uint8_t arg2);

// ── Phase 3 Step 3: VectorDB — cosine similarity guidance ─────────────────────
//
// Three reference vectors (per-slot danger patterns, slot-agnostic):
//   REF_ALARM_SKIP   — voted_notar pre-crash + post-crash + skip votes accumulating
//   REF_AMNESIA      — notar_cert pre-crash + post-crash activity (amnesia gap)
//   REF_DUAL_CERT    — notar_cert + cert_skip simultaneously
//
// After each LLVMFuzzerTestOneInput, we compute max cosine similarity between
// g_state_counters and each reference pattern across all 16 slots, then emit
// __sanitizer_cov_trace_cmp1 pairs encoding the similarity score.
// libFuzzer (-use_value_profile=1) treats higher similarity as new coverage →
// gradient descent toward dangerous states without Faiss/hnswlib.
//
// ref_pattern[i] uses indices relative to slot base (0..7):
//   0=SE_NOTAR_VOTE 1=SE_SKIP_VOTE 2=SE_FINAL_VOTE 3=SE_NOTAR_CERT
//   4=SE_POST_CRASH 5=SE_BOTH_NS   6=SE_CERT_SKIP  7=SE_FINAL_CERT

static const float REF_ALARM_SKIP[SE_STRIDE] = {
  255.f,  // SE_NOTAR_VOTE:  our node voted notarize (pre-crash)
  200.f,  // SE_SKIP_VOTE:   skip votes accumulating (post-crash quorum forming)
    0.f,  // SE_FINAL_VOTE
  255.f,  // SE_NOTAR_CERT:  notarize cert observed (pre-crash)
  200.f,  // SE_POST_CRASH:  post-crash activity on this slot
    0.f,  // SE_BOTH_NS
    0.f,  // SE_CERT_SKIP
    0.f,  // reserved
};

static const float REF_AMNESIA[SE_STRIDE] = {
  255.f,  // SE_NOTAR_VOTE:  our vote was broadcast before crash
    0.f,  // SE_SKIP_VOTE
    0.f,  // SE_FINAL_VOTE
  255.f,  // SE_NOTAR_CERT:  notar cert formed
  255.f,  // SE_POST_CRASH:  now in post-crash phase
    0.f,  // SE_BOTH_NS
    0.f,  // SE_CERT_SKIP
    0.f,  // reserved
};

static const float REF_DUAL_CERT[SE_STRIDE] = {
    0.f,  // SE_NOTAR_VOTE
    0.f,  // SE_SKIP_VOTE
    0.f,  // SE_FINAL_VOTE
  255.f,  // SE_NOTAR_CERT:  notarize cert present
    0.f,  // SE_POST_CRASH
    0.f,  // SE_BOTH_NS
  255.f,  // SE_CERT_SKIP:   skip cert also present → alarm-skip dual-cert
    0.f,  // SE_FINAL_CERT
};

// State divergence: FinalCert issued on a skipped slot → SkipCert ∧ FinalCert ⇒ ⊥
static const float REF_STATE_DIV[SE_STRIDE] = {
    0.f,  // SE_NOTAR_VOTE
    0.f,  // SE_SKIP_VOTE
  255.f,  // SE_FINAL_VOTE:  finalize votes accumulating
    0.f,  // SE_NOTAR_CERT
    0.f,  // SE_POST_CRASH
    0.f,  // SE_BOTH_NS
  255.f,  // SE_CERT_SKIP:   skip cert present
  255.f,  // SE_FINAL_CERT:  final cert present → violation
};

// Liveness: windows advance but no cert ever issues — protocol stuck under Byzantine pressure.
// Target: many skip votes + windows advancing + no notarize/finalize cert.
static const float REF_LIVENESS[SE_STRIDE] = {
    0.f,  // SE_NOTAR_VOTE:  no notarize vote (Byzantine suppresses proposals)
  255.f,  // SE_SKIP_VOTE:   skip votes accumulating (timeouts firing)
    0.f,  // SE_FINAL_VOTE
    0.f,  // SE_NOTAR_CERT:  no cert (that's the liveness failure)
    0.f,  // SE_POST_CRASH
    0.f,  // SE_BOTH_NS
    0.f,  // SE_CERT_SKIP
    0.f,  // SE_FINAL_CERT
};

static float cosine_sim_slot(const float* ref, const uint8_t* counters_at_base) {
  float dot = 0.f, na = 0.f, nb = 0.f;
  for (int i = 0; i < SE_STRIDE; i++) {
    float a = ref[i];
    float b = static_cast<float>(counters_at_base[i]);
    dot += a * b;
    na  += a * a;
    nb  += b * b;
  }
  if (na < 1e-9f || nb < 1e-9f) return 0.f;
  return dot / std::sqrt(na * nb);
}

// Shared with fuzz_pool_mutator.cpp — mutator reads these to bias op selection.
// g_last_sim[r] = max cosine similarity with refs[r] across all 16 slots,
// computed at the end of the previous TestOneInput call.
float g_last_sim[5] = {};

// Emit similarity scores for all five reference vectors across all slots.
// Channel byte: 0xA0 + r*0x10 + slot — unique per (ref, slot) pair.
// Also updates g_last_sim[r] = max(sim) across slots, for the mutator.
static void emit_vector_guidance() {
  const float* refs[5] = {REF_ALARM_SKIP, REF_AMNESIA, REF_DUAL_CERT, REF_STATE_DIV, REF_LIVENESS};
  for (int r = 0; r < 5; r++) {
    float max_sim = 0.f;
    for (int slot = 0; slot < 16; slot++) {
      float sim = cosine_sim_slot(refs[r], &g_state_counters[slot * SE_STRIDE]);
      if (sim > max_sim) max_sim = sim;
      auto sim_byte = static_cast<uint8_t>(sim * 255.f);
      auto channel  = static_cast<uint8_t>(0xA0 + r * 0x10 + slot);
      __sanitizer_cov_trace_cmp1(channel, sim_byte);
    }
    g_last_sim[r] = max_sim;
  }
}

enum SlotEvent : int {
  SE_NOTAR_VOTE = 0,
  SE_SKIP_VOTE  = 1,
  SE_FINAL_VOTE = 2,
  SE_NOTAR_CERT  = 3,
  SE_POST_CRASH  = 4,
  SE_BOTH_NS     = 5,
  SE_CERT_SKIP   = 6,
  SE_FINAL_CERT  = 7,
};

static bool g_post_crash_phase = false;

static void slot_event(int32_t slot_i32, SlotEvent ev) {
  if (slot_i32 < 0 || slot_i32 >= 16) return;
  auto slot = static_cast<uint8_t>(slot_i32);
  int base = slot * SE_STRIDE;
  g_state_counters[base + ev]++;

  // Emit value-profile pairs so libFuzzer (-use_value_profile=1) treats
  // new state combinations as new "coverage":

  // Tracks per-slot correlation of notarize vs skip votes.
  // A new (notar_count, skip_count) pair = new dangerous combo explored.
  __sanitizer_cov_trace_cmp1(g_state_counters[base + SE_NOTAR_VOTE],
                              g_state_counters[base + SE_SKIP_VOTE]);

  // Danger: notarize cert already exists, skip votes accumulating.
  if (g_state_counters[base + SE_NOTAR_CERT]) {
    __sanitizer_cov_trace_cmp1(static_cast<uint8_t>(slot | 0x80),
                                g_state_counters[base + SE_SKIP_VOTE]);
  }

  // Post-crash: any activity on a slot that had a NotarCert before crash.
  if (g_post_crash_phase && g_state_counters[base + SE_NOTAR_CERT]) {
    __sanitizer_cov_trace_cmp1(static_cast<uint8_t>(slot | 0xC0),
                                static_cast<uint8_t>(ev));
  }

  // Update internal danger counters (used by g_notar_by_slot checks).
  if (g_state_counters[base + SE_NOTAR_VOTE] && g_state_counters[base + SE_SKIP_VOTE]) {
    g_state_counters[base + SE_BOTH_NS]++;
  }
  if (g_state_counters[base + SE_NOTAR_CERT] && g_state_counters[base + SE_SKIP_VOTE]) {
    g_state_counters[base + SE_CERT_SKIP]++;
  }
  if (g_post_crash_phase) {
    g_state_counters[base + SE_POST_CRASH]++;
  }
}

// ─────────────────────────────────────────────────────────────────────────────

namespace ton::validator::consensus::simplex {

// ── MockDb ────────────────────────────────────────────────────────────────────

class MockDb final : public consensus::Db {
 public:
  std::optional<td::BufferSlice> get(td::Slice key) const override {
    auto it = kv_.find(key.str());
    if (it == kv_.end()) return std::nullopt;
    return it->second.clone();
  }

  std::vector<std::pair<td::BufferSlice, td::BufferSlice>> get_by_prefix(td::uint32 prefix) const override {
    std::vector<std::pair<td::BufferSlice, td::BufferSlice>> result;
    for (const auto& [k, v] : kv_) {
      if (k.size() >= 4 && std::memcmp(k.data(), &prefix, 4) == 0) {
        result.emplace_back(td::BufferSlice(k), v.clone());
      }
    }
    return result;
  }

  td::actor::Task<> set(td::BufferSlice key, td::BufferSlice value) override {
    auto ks = key.as_slice().str();
    // WAL semantics: log every write (including updates) with previous value so
    // crash_losing_last_n can properly undo the exact writes that were in-flight.
    // Previously, only new-key insertions were logged, so updates to pool_state
    // (first_nonannounced_window) could not be "lost" — making the alarm-skip path
    // unreachable because window 1 → first_nonannounced_window=2 persisted across crash.
    auto it = kv_.find(ks);
    write_log_.push_back({ks, it != kv_.end() ? std::make_optional(it->second.clone()) : std::nullopt});
    kv_[ks] = std::move(value);
    co_return {};
  }

  // Discard the last `n` writes (crash simulation). Undoes updates by restoring
  // previous values; undoes insertions by erasing the key entirely.
  void crash_losing_last_n(size_t n) {
    n = std::min(n, write_log_.size());
    for (size_t i = 0; i < n; i++) {
      auto& entry = write_log_.back();
      if (entry.prev.has_value()) {
        kv_[entry.key] = std::move(*entry.prev);
      } else {
        kv_.erase(entry.key);
      }
      write_log_.pop_back();
    }
  }

  // Discard every stride-th write from the back, up to n total losses.
  // stride=1 is identical to crash_losing_last_n. stride=2 removes alternating
  // entries (leaves gaps in the WAL), stride=3 removes every third, etc.
  // Models selective media corruption or partial-flush scenarios where not all
  // in-flight pages are lost — only a subset spread across the write sequence.
  void crash_losing_stride_n(size_t n, size_t stride) {
    if (stride <= 1) { crash_losing_last_n(n); return; }
    n = std::min(n, (write_log_.size() + stride - 1) / stride);
    size_t removed = 0;
    for (ptrdiff_t i = static_cast<ptrdiff_t>(write_log_.size()) - 1;
         i >= 0 && removed < n; i -= static_cast<ptrdiff_t>(stride)) {
      auto& entry = write_log_[static_cast<size_t>(i)];
      if (entry.prev.has_value()) {
        kv_[entry.key] = std::move(*entry.prev);
      } else {
        kv_.erase(entry.key);
      }
      write_log_.erase(write_log_.begin() + i);
      ++removed;
    }
  }

  // Discard the first `n` writes (crash simulation — earliest entries in WAL).
  // Simulates corruption of the oldest records (e.g. early-session cert loss)
  // rather than the most-recent in-flight writes. Complements crash_losing_last_n.
  void crash_losing_first_n(size_t n) {
    n = std::min(n, write_log_.size());
    for (size_t i = 0; i < n; i++) {
      auto& entry = write_log_[i];
      if (entry.prev.has_value()) {
        kv_[entry.key] = std::move(*entry.prev);
      } else {
        kv_.erase(entry.key);
      }
    }
    write_log_.erase(write_log_.begin(), write_log_.begin() + static_cast<ptrdiff_t>(n));
  }

  // Deep-copy the current (post-crash) DB state for the recovery bus.
  // write_log_ is intentionally not copied: recovered DB starts a fresh log.
  std::unique_ptr<MockDb> clone() const {
    auto db = std::make_unique<MockDb>();
    for (const auto& [k, v] : kv_) {
      db->kv_[k] = v.clone();
    }
    return db;
  }

 private:
  struct WriteEntry {
    std::string key;
    std::optional<td::BufferSlice> prev;  // nullopt = key was newly inserted
  };

  std::map<std::string, td::BufferSlice> kv_;
  std::vector<WriteEntry> write_log_;
};

// ── MockKeyring ───────────────────────────────────────────────────────────────
//
// bootstrap_votes replay calls co_await keyring::sign_message on restart.
// Since g_skip_signature_check=true the actual bytes don't matter.

class MockKeyring final : public keyring::Keyring {
 public:
  void add_key(PrivateKey, bool, td::Promise<td::Unit> p) override { p.set_value({}); }
  void check_key(PublicKeyHash, td::Promise<td::Unit> p) override { p.set_value({}); }
  void add_key_short(PublicKeyHash, td::Promise<PublicKey> p) override { p.set_error(td::Status::Error("mock")); }
  void del_key(PublicKeyHash, td::Promise<td::Unit> p) override { p.set_value({}); }
  void export_private_key(PublicKeyHash, td::Promise<PrivateKey> p) override { p.set_error(td::Status::Error("mock")); }
  void get_public_key(PublicKeyHash, td::Promise<PublicKey> p) override { p.set_error(td::Status::Error("mock")); }
  void sign_message(PublicKeyHash, td::BufferSlice, td::Promise<td::BufferSlice> p) override {
    p.set_value(td::BufferSlice(64));
  }
  void sign_add_get_public_key(PublicKeyHash, td::BufferSlice,
                                td::Promise<std::pair<td::BufferSlice, PublicKey>> p) override {
    p.set_error(td::Status::Error("mock"));
  }
  void sign_messages(PublicKeyHash, std::vector<td::BufferSlice> data,
                     td::Promise<std::vector<td::Result<td::BufferSlice>>> p) override {
    std::vector<td::Result<td::BufferSlice>> res;
    res.reserve(data.size());
    for (size_t i = 0; i < data.size(); i++) res.emplace_back(td::BufferSlice(64));
    p.set_value(std::move(res));
  }
  void decrypt_message(PublicKeyHash, td::BufferSlice, td::Promise<td::BufferSlice> p) override {
    p.set_error(td::Status::Error("mock"));
  }
  void export_all_private_keys(td::Promise<std::vector<PrivateKey>> p) override { p.set_value({}); }
};

// ── FuzzBus ───────────────────────────────────────────────────────────────────

class FuzzBus final : public Bus {
 public:
  // Required so the actor framework walks simplex::Bus → consensus::Bus in the
  // bus-type inheritance chain when wire_bus() spawns Pool / Db / ConsensusImpl.
  using Parent = Bus;

  void populate_collator_schedule() override {
    Bus::populate_collator_schedule();
  }
};

// Invariant-tracking globals (written by FuzzObserver, checked inline).
// Intentionally persist across crash+restart to catch cross-boundary violations.
static uint64_t g_run_id = 0;
static uint64_t g_invocation = 0;
static std::map<td::uint32, std::pair<uint64_t, td::Bits256>> g_notar_by_slot;
static std::map<td::uint32, std::pair<uint64_t, td::Bits256>> g_skip_by_slot;
static std::map<td::uint32, std::pair<uint64_t, td::Bits256>> g_final_by_slot;
// Amnesia equivocation tracking: val 0's individual NotarizeVotes per slot.
// Populated from OutgoingProtocolMessage (all such messages come from the local node).
// Trap if two different hashes for the same slot within the same run → amnesia.
static std::map<td::uint32, std::pair<uint64_t, td::Bits256>> g_our_notar_vote;
// Safety traps are only active during the main test body, not during
// start-of-run reset drains or end-of-run flush drains. This prevents the
// scheduler's asynchronous certificate delivery from triggering a cross-run
// false positive when a SkipCert queued by run N is delivered during run N+1.
static bool g_safety_active = false;

// ── FuzzObserver ──────────────────────────────────────────────────────────────

using FuzzBusHandle = td::actor::BusHandle<FuzzBus>;

class FuzzObserver final : public td::actor::SpawnsWith<FuzzBus>,
                           public td::actor::ConnectsTo<FuzzBus> {
 public:
  TON_RUNTIME_DEFINE_EVENT_HANDLER();

  explicit FuzzObserver(FuzzBus&) {}

  template <>
  void handle(FuzzBusHandle, std::shared_ptr<const StopRequested>) {
    stop();
  }

  template <>
  void handle(FuzzBusHandle, std::shared_ptr<const NotarizationObserved> ev) {
    td::uint32 slot = ev->certificate->vote.id.slot;
    auto hash = ev->certificate->vote.id.hash;
    if (g_safety_active) {
      // #dual-notar-cert: two NotarCerts with different blocks on the same slot = safety violation.
      // Re-added (previously removed as "vtype=7 only"): vtype=7 also tests a realistic
      // Byzantine scenario where ConsensusImpl receives conflicting NotarizationObserved events.
      auto it = g_notar_by_slot.find(slot);
      if (it != g_notar_by_slot.end() && it->second.first == g_run_id
          && it->second.second != hash) {
        __builtin_trap();  // #dual-notar-cert: conflicting NotarCerts same slot
      }
      // #notar-skip-cert: NotarCert on a slot that already has a SkipCert = safety violation.
      auto skip_it = g_skip_by_slot.find(slot);
      if (skip_it != g_skip_by_slot.end() && skip_it->second.first == g_run_id) {
        __builtin_trap();  // #notar-skip-cert: NotarCert on SkipCert'd slot
      }
    }
    g_notar_by_slot.emplace(slot, std::make_pair(g_run_id, hash));

    // Step 4: state counter
    slot_event(static_cast<int32_t>(slot), SE_NOTAR_CERT);
    if (g_post_crash_phase) g_state_counters[130]++;
  }

  template <>
  void handle(FuzzBusHandle, std::shared_ptr<const FinalizationObserved> ev) {
    td::uint32 slot = ev->id.slot;
    auto hash = ev->id.hash;
    // Phase 5.18: re-added traps for FinalCert conflicts (confirmed via vtype=0,1,2 + WAL crash).
    // Earlier note "only via vtype=7" was incorrect — regular injection also triggers these.
    // Findings documented in VULN_STATE_DIVERGENCE.md §5.18:
    //   crash-4d339b (44б): SkipCert+FinalCert on same slot → pool.cpp:954 CHECK
    //   crash-a54ed333 (44б): NotarCert(A)+FinalCert(B≠A) → pool.cpp:955 CHECK
    if (g_safety_active) {
      // skip-finalize conflict
      auto skip_it = g_skip_by_slot.find(slot);
      if (skip_it != g_skip_by_slot.end() && skip_it->second.first == g_run_id) {
        __builtin_trap();  // #skip-finalize: FinalCert on SkipCert'd slot
      }
      // notar-finalize mismatch
      auto notar_it = g_notar_by_slot.find(slot);
      if (notar_it != g_notar_by_slot.end() && notar_it->second.first == g_run_id
          && notar_it->second.second != hash) {
        __builtin_trap();  // #notar-finalize-mismatch: FinalCert for wrong block
      }
    }
    if (g_safety_active) {
      // #dual-final-cert: two FinalCerts with different blocks on the same slot = safety violation.
      auto final_it = g_final_by_slot.find(slot);
      if (final_it != g_final_by_slot.end() && final_it->second.first == g_run_id
          && final_it->second.second != hash) {
        __builtin_trap();  // #dual-final-cert: conflicting FinalCerts same slot
      }
    }
    g_final_by_slot.emplace(slot, std::make_pair(g_run_id, hash));
    slot_event(static_cast<int32_t>(slot), SE_FINAL_CERT);
  }

  // Step 4: track window progression
  template <>
  void handle(FuzzBusHandle, std::shared_ptr<const LeaderWindowObserved>) {
    g_state_counters[129]++;
  }

  // Step 4 + Phase 3 Step 2: parse outgoing messages — votes and certificates.
  // SkipCert detection enables alarm-skip-after-notarize safety check.
  template <>
  void handle(FuzzBusHandle, std::shared_ptr<const OutgoingProtocolMessage> msg) {
    // Try certificate first (certificate TL id != vote TL id).
    auto maybe_cert = fetch_tl_object<ton_api::consensus_simplex_certificate>(
        msg->message.data.clone(), true);
    if (maybe_cert.is_ok()) {
      auto& cert = *maybe_cert.ok();
      auto* uv = cert.vote_.get();
      if (uv && uv->get_id() == ton_api::consensus_simplex_skipVote::ID) {
        auto* sv = static_cast<ton_api::consensus_simplex_skipVote*>(uv);
        td::uint32 slot = static_cast<td::uint32>(sv->slot_);
        g_skip_by_slot.emplace(slot, std::make_pair(g_run_id, td::Bits256{}));
        slot_event(static_cast<int32_t>(slot), SE_CERT_SKIP);
        // Safety: SkipCert on a slot that already has a NotarCert or FinalCert → violation.
        // Traps removed: alarm-skip finding documented in VULN_ALARM_SKIP.md.
        // State tracking preserved so fuzzer can explore post-alarm-skip paths.
        if (g_safety_active) {
          auto notar_it = g_notar_by_slot.find(slot);
          (void)notar_it;  // alarm-skip: documented, trap removed
          auto final_it = g_final_by_slot.find(slot);
          (void)final_it;  // alarm-skip+final: documented, trap removed
        }
      }
      return;
    }

    auto maybe_vote = fetch_tl_object<ton_api::consensus_simplex_vote>(
        msg->message.data.clone(), true);
    if (maybe_vote.is_error()) return;
    auto& v = *maybe_vote.ok();
    auto* uv = v.vote_.get();
    if (!uv) return;
    switch (uv->get_id()) {
      case ton_api::consensus_simplex_notarizeVote::ID: {
        auto* nv = static_cast<ton_api::consensus_simplex_notarizeVote*>(uv);
        if (nv->id_) {
          slot_event(nv->id_->slot_, SE_NOTAR_VOTE);
          // Amnesia equivocation trap: val 0 voted twice on same slot with different cand.
          td::uint32 slot = static_cast<td::uint32>(nv->id_->slot_);
          td::Bits256 hash = nv->id_->hash_;
          auto [it, inserted] = g_our_notar_vote.emplace(slot, std::make_pair(g_run_id, hash));
          // Amnesia equivocation: documented in VULN_AMNESIA_POC.md, trap removed to allow coverage growth.
          (void)inserted;
          if (!inserted) it->second = {g_run_id, hash};
        }
        break;
      }
      case ton_api::consensus_simplex_skipVote::ID: {
        auto* sv = static_cast<ton_api::consensus_simplex_skipVote*>(uv);
        slot_event(sv->slot_, SE_SKIP_VOTE);
        break;
      }
      case ton_api::consensus_simplex_finalizeVote::ID: {
        auto* fv = static_cast<ton_api::consensus_simplex_finalizeVote*>(uv);
        if (fv->id_) slot_event(fv->id_->slot_, SE_FINAL_VOTE);
        break;
      }
    }
  }

  // Phase 3 Step 2: stub resolvers so Consensus coroutines abort gracefully
  // instead of hanging forever when StateResolver / CandidateResolver are absent.
  //
  // Phase 4 Step 2 (validation): ResolveState returns valid zerostate ChainStateRef,
  // ValidationRequest returns CandidateAccept — together they allow try_notarize() to
  // complete end-to-end (store_candidate + NotarizeVote emission) for vtype=3 Propose.
  // ResolveCandidate still returns error (candidate resolution not needed for voting).
  // OurLeaderWindowStarted is published but has no handler in harness → ignored safely.

  template <>
  td::actor::Task<ResolveState::Result> process(FuzzBusHandle, std::shared_ptr<ResolveState>) {
    // Return a valid zerostate so try_notarize() can reach ValidationRequest.
    // Previously returned error, which caused try_notarize() to abort before
    // ValidationRequest, leaving the candidate-finalization path uncovered.
    auto zerostate_id = BlockIdExt{BlockId{ton::basechainId, ton::shardIdAll, 0}};
    auto chain_state = ChainState::from_zerostate(zerostate_id, vm::CellBuilder().finalize(), zerostate_id);
    co_return ResolveState::Result{.state = chain_state};
  }

  template <>
  td::actor::Task<ValidateCandidateResult> process(FuzzBusHandle, std::shared_ptr<ValidationRequest>) {
    // Accept all candidates: allows ConsensusImpl to emit NotarizeVote via try_notarize().
    co_return CandidateAccept{0.0};
  }

  template <>
  void handle(FuzzBusHandle, std::shared_ptr<const TraceEvent>) {}

  template <>
  void handle(FuzzBusHandle, std::shared_ptr<const MisbehaviorReport>) {}
};

}  // namespace ton::validator::consensus::simplex

// ── Global fuzz state ─────────────────────────────────────────────────────────

using namespace ton;
using namespace ton::validator;
using namespace ton::validator::consensus;
using namespace ton::validator::consensus::simplex;

struct FuzzState {
  std::unique_ptr<td::actor::Scheduler> scheduler;
  std::shared_ptr<td::actor::Runtime> runtime;
  td::actor::BusHandle<FuzzBus> bus;
  td::actor::ActorOwn<MockKeyring> keyring;
  MockDb* db_raw = nullptr;
  ValidatorSessionId session_id;
  td::Bits256 cand_hashes[N_CAND_SEEDS];
};

static FuzzState* g_state = nullptr;

// ── Bus configuration helper ──────────────────────────────────────────────────

static void configure_and_start_bus(FuzzState& S, std::unique_ptr<MockDb> db) {
  S.db_raw = db.get();

  auto bus = std::make_shared<FuzzBus>();
  bus->session_id = S.session_id;
  bus->shard = ShardIdFull{basechainId, shardIdAll};
  bus->cc_seqno = 0;
  bus->simplex_config.slots_per_leader_window = 4;
  bus->simplex_config.max_leader_window_desync = 2;

  bus->validator_set.resize(N_VALIDATORS);
  bus->total_weight = 0;
  for (size_t i = 0; i < N_VALIDATORS; i++) {
    td::Bits256 key_bits{};
    key_bits.as_array()[0] = static_cast<uint8_t>(i + 1);
    PublicKey pub{pubkeys::Ed25519{key_bits}};
    bus->validator_set[i] = PeerValidator{
        .idx = PeerValidatorId{i},
        .key = pub,
        .short_id = pub.compute_short_id(),
        .weight = 1,
    };
    bus->total_weight += 1;
  }
  bus->local_id = bus->validator_set[0];
  bus->populate_collator_schedule();
  bus->keyring = S.keyring.get();
  bus->db = std::move(db);

  S.runtime = std::make_shared<td::actor::Runtime>();
  Pool::register_in(*S.runtime);
  simplex::Db::register_in(*S.runtime);
  Consensus::register_in(*S.runtime);  // Phase 3 Step 2: enables alarm-skip path via start_up()
  CandidateResolver::register_in(*S.runtime);  // enables IncomingOverlayRequest (vtype=6)
  S.runtime->register_actor<FuzzObserver>("FuzzObserver");

  S.scheduler->run_in_context([&] {
    S.bus = S.runtime->start(std::move(bus), "fuzz_pool");
  });

  for (int i = 0; i < DRAIN_ROUNDS; i++) {
    S.scheduler->run(0);
  }

  // Publish Start so Pool sets is_started_=true.
  // Without this, advance_present() returns immediately, first_nonannounced_window
  // is never written to WAL, and ConsensusImpl::start_up() on restart cannot
  // broadcast SkipVotes — the alarm-skip-after-notarize path is unreachable.
  S.scheduler->run_in_context([&] {
    S.bus.publish(std::make_shared<Start>(Start{ChainStateRef{}}));
  });
  for (int i = 0; i < DRAIN_ROUNDS; i++) {
    S.scheduler->run(0);
  }
}

// ── WAL crash-and-restart ─────────────────────────────────────────────────────

// lose_mode: 0=last N, 1=first N, 2+=stride (2→stride 2, 3→stride 3, 4→stride 4)
static void crash_and_restart(FuzzState& S, size_t n_lose, uint8_t lose_mode = 0) {
  if (lose_mode == 1)
    S.db_raw->crash_losing_first_n(n_lose);
  else if (lose_mode >= 2)
    S.db_raw->crash_losing_stride_n(n_lose, lose_mode);
  else
    S.db_raw->crash_losing_last_n(n_lose);
  auto recovered_db = S.db_raw->clone();

  S.scheduler->run_in_context([&] {
    S.bus.publish(std::make_shared<StopRequested>());
  });
  // Drain scheduler until all pending WaitForParent promises are resolved
  // (g_pending_requests_count == 0, set by PoolImpl::tear_down()), then run
  // EXTRA_DRAIN_AFTER_TEARDOWN more rounds so WaitForParent coroutine
  // continuations fully unwind before runtime.reset() — prevents SEGV in
  // ActorMessageCoroutineSafe::~dtor → SchedulerExecutor::schedule.
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
  {
    namespace simplex = ton::validator::consensus::simplex;
    int extra = 0;
    for (int i = 0; i < DRAIN_CRASH_ROUNDS; i++) {
      S.scheduler->run(0);
      if (simplex::g_pending_requests_count.load() == 0) {
        if (++extra >= EXTRA_DRAIN_AFTER_TEARDOWN) break;
      } else {
        extra = 0;  // counter went back up (shouldn't happen, but reset if so)
      }
    }
  }
#else
  for (int i = 0; i < DRAIN_CRASH_ROUNDS; i++) {
    S.scheduler->run(0);
  }
#endif

  S.bus = {};
  S.runtime.reset();

  g_post_crash_phase = true;
  g_state_counters[128]++;  // GC_CRASHED

  configure_and_start_bus(S, std::move(recovered_db));
}

// ── One-time initialization ───────────────────────────────────────────────────

extern "C" int LLVMFuzzerInitialize(int*, char***) {
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(ERROR));
  simulation::GraphLogger::instance().init();
  PeerValidator::g_skip_signature_check = true;

  // g_state_counters are used internally; value-profile pairs are emitted
  // via __sanitizer_cov_trace_cmp1 in slot_event() (Step 4).
  // Run with: -use_value_profile=1 to enable semantic coverage guidance.

  g_state = new FuzzState();
  auto& S = *g_state;

  S.session_id = td::Bits256{};
  S.session_id.as_array()[0] = 0x42;
  for (size_t i = 0; i < N_CAND_SEEDS; i++) {
    S.cand_hashes[i] = td::Bits256{};
    S.cand_hashes[i].as_array()[0] = static_cast<uint8_t>(i + 1);
  }

  // NodeInfo{{0}}: zero CPU threads → all actors route to the IO queue, which is
  // drained synchronously by run(0) on the main thread. NodeInfo{{1}} would create
  // a background CPU thread and make actor execution non-deterministic / async
  // (messages processed concurrently with inject_vote drain rounds).
  S.scheduler = std::make_unique<td::actor::Scheduler>(
      std::vector<td::actor::Scheduler::NodeInfo>{{0}}, /*skip_timeouts=*/true);

  S.scheduler->run_in_context([&] {
    S.keyring = td::actor::create_actor<MockKeyring>(
        td::actor::ActorOptions{}.with_name("MockKeyring"));
  });

  configure_and_start_bus(S, std::make_unique<MockDb>());

  return 0;
}

// ── Per-iteration fuzzing ─────────────────────────────────────────────────────

// Inject a single vote message into the bus and drain the scheduler.
// ── Message buffering for permutation ────────────────────────────────────────

struct MsgSpec {
  uint8_t src_idx;
  uint8_t vote_type;
  uint8_t slot;
  uint8_t cand_seed;
  std::vector<uint8_t> raw_bytes;  // used by vote_type 4 and 6 only
};

// Flood WEIGHT_THRESHOLD SkipVotes for `slot` — helper for vtype=10, vtype=15, n_windows.
// Forms a SkipCert deterministically; also drains the scheduler after each vote.
static void skip_flood_slot(uint8_t slot) {
  auto& S = *g_state;
  for (size_t v = 1; v <= WEIGHT_THRESHOLD; v++) {
    auto vtl = create_tl_object<ton_api::consensus_simplex_skipVote>(static_cast<int32_t>(slot));
    auto svtl = create_tl_object<ton_api::consensus_simplex_vote>(std::move(vtl), td::BufferSlice(64));
    auto bytes = serialize_tl_object(svtl, true);
    auto msg = std::make_shared<IncomingProtocolMessage>(
        PeerValidatorId{static_cast<uint8_t>(v)}, ProtocolMessage{std::move(bytes)});
    S.scheduler->run_in_context([&] { S.bus.publish(msg); });
    for (int i = 0; i < DRAIN_ROUNDS; i++) S.scheduler->run(0);
  }
}

// Read one message spec from fdp without injecting it yet.
static std::optional<MsgSpec> read_msg_spec(FuzzedDataProvider& fdp) {
  if (fdp.remaining_bytes() < 4) return std::nullopt;
  MsgSpec spec;
  spec.src_idx   = fdp.ConsumeIntegralInRange<uint8_t>(1, N_VALIDATORS - 1);
  spec.vote_type = fdp.ConsumeIntegralInRange<uint8_t>(0, 14);
  spec.slot      = fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_SLOT);
  spec.cand_seed = fdp.ConsumeIntegralInRange<uint8_t>(0, N_CAND_SEEDS - 1);
  if (spec.vote_type == 4 || spec.vote_type == 6) {
    auto raw_len = static_cast<size_t>(spec.slot);
    spec.raw_bytes = fdp.ConsumeBytes<uint8_t>(raw_len);
  }
  return spec;
}

// Inject a previously read MsgSpec into the bus.
static void inject_from_spec(const MsgSpec& spec);

static void inject_vote(FuzzedDataProvider& fdp) {
  if (auto spec = read_msg_spec(fdp)) inject_from_spec(*spec);
}

static void inject_from_spec(const MsgSpec& spec) {
  auto& S = *g_state;
  auto src_idx   = spec.src_idx;
  auto vote_type = spec.vote_type;
  auto slot      = spec.slot;
  auto cand_seed = spec.cand_seed;

  // vtype=6: IncomingOverlayRequest — fuzz CandidateResolver TL parsing path.
  // Sends raw bytes as overlay request via CandidateResolver (candidate-resolver.cpp:131):
  // fetch_tl_object<tl::requestCandidate> → candidate state lookup → response.
  // CandidateResolver::register_in() enables this path; tear_down() via StopRequested
  // resolves pending awaiters cleanly. slot byte reused as raw_len (0..15).
  if (vote_type == 6) {
    // raw_bytes populated by read_msg_spec (or empty for legacy inject_vote path).
    const auto& raw_bytes = spec.raw_bytes;
    // Guard: empty vector.data() may be nullptr → td::Slice(nullptr,0) CHECK fails.
    td::BufferSlice payload = raw_bytes.empty()
        ? td::BufferSlice()
        : td::BufferSlice(reinterpret_cast<const char*>(raw_bytes.data()), raw_bytes.size());
    auto ev = std::make_shared<IncomingOverlayRequest>(
        PeerValidatorId{src_idx},
        ProtocolMessage{std::move(payload)});
    S.scheduler->run_in_context([&] { S.bus.publish(ev); });
    for (int i = 0; i < DRAIN_ROUNDS; i++) S.scheduler->run(0);
    return;
  }

  // vtype=5: BroadcastVote — injects Vote via handle_our_vote (local validator path).
  // Unlike vtype=0,1,2 which inject peer votes via IncomingProtocolMessage, this goes
  // through pool.cpp:484 → handle_our_vote → keyring sign → handle_vote(local_id).
  // Covers tolerate_conflicts=false local vote path. slot%3 selects vote variant.
  if (vote_type == 5) {
    uint8_t sub = slot % 3;
    CandidateId cid{.slot = slot, .hash = S.cand_hashes[cand_seed]};
    Vote vote = (sub == 0) ? Vote{NotarizeVote{cid}}
              : (sub == 1) ? Vote{SkipVote{.slot = slot}}
                           : Vote{FinalizeVote{cid}};
    auto ev = std::make_shared<BroadcastVote>(BroadcastVote{std::move(vote)});
    S.scheduler->run_in_context([&] { S.bus.publish(ev); });
    for (int i = 0; i < DRAIN_ROUNDS; i++) S.scheduler->run(0);
    return;
  }

  // vtype=4: Raw IncomingProtocolMessage — fuzz TL deserialization path directly.
  // Unlike vtype=0,1,2 which inject pre-serialized votes, this sends raw bytes through
  // pool.cpp:391 (fetch_tl_object<tl::vote> + fetch_tl_object<tl::certificate>).
  // Covers the certificate handling path (pool.cpp:436+) unreachable via typed injection.
  // slot byte is reused as raw_len (0..MAX_SLOT); cand_seed byte is the first raw byte.
  if (vote_type == 4) {
    // raw_bytes populated by read_msg_spec (or empty for legacy inject_vote path).
    const auto& raw_bytes = spec.raw_bytes;
    td::BufferSlice payload4 = raw_bytes.empty()
        ? td::BufferSlice()
        : td::BufferSlice(reinterpret_cast<const char*>(raw_bytes.data()), raw_bytes.size());
    auto msg = std::make_shared<IncomingProtocolMessage>(
        PeerValidatorId{src_idx},
        ProtocolMessage{std::move(payload4)});
    S.scheduler->run_in_context([&] { S.bus.publish(msg); });
    for (int i = 0; i < DRAIN_ROUNDS; i++) S.scheduler->run(0);
    return;
  }

  // vtype=3: Propose injection — publish CandidateReceived{slot, cand_seed} directly.
  // Triggers ConsensusImpl::try_notarize() → ResolveState (returns valid zerostate)
  //   → ValidationRequest (returns CandidateAccept) → store_candidate → NotarizeVote emitted.
  // slot=0: parent=nullopt, WaitForParent resolves immediately (next_slot_after_parent==0==slot).
  // slot>0: parent=CandidateId{slot-1, cand_seed}, WaitForParent stays pending until parent
  //   is notarized → requests_ grows → #request-no-bound trap fires at size >= 4.
  // Previously clamped to slot=0 to avoid SEGV; now safe because LLVMFuzzerTestOneInput
  // publishes StopRequested before delete g_state → tear_down() resolves all pending requests.
  // src_idx is used as the leader (PeerValidatorId of the proposer).
  if (vote_type == 3) {
    CandidateId cand_id{.slot = slot, .hash = S.cand_hashes[cand_seed]};
    ParentId parent_id = slot > 0
        ? std::make_optional(CandidateId{.slot = static_cast<td::uint32>(slot - 1),
                                         .hash = S.cand_hashes[cand_seed]})
        : std::nullopt;  // slot 0: no parent; resolves immediately
    BlockCandidate bc{};
    bc.id = BlockIdExt{BlockId{basechainId, shardIdAll, 0}};
    // Provide minimal valid BoC so CandidateResolver can serialize/store without crashing.
    // Empty BlockCandidate.data triggers compress_candidate_data → boc.deserialize("") → error.
    auto empty_cell = vm::CellBuilder().finalize();
    bc.data = vm::std_boc_serialize(empty_cell, 31).move_as_ok();
    bc.collated_data = vm::std_boc_serialize_multi({empty_cell}, 2).move_as_ok();
    auto candidate = td::make_ref<Candidate>(
        cand_id, parent_id, PeerValidatorId{src_idx},
        std::variant<BlockIdExt, BlockCandidate>(std::in_place_type<BlockCandidate>, std::move(bc)),
        td::BufferSlice(64));
    auto ev = std::make_shared<CandidateReceived>(CandidateReceived{std::move(candidate)});
    S.scheduler->run_in_context([&] { S.bus.publish(ev); });
    for (int i = 0; i < DRAIN_ROUNDS; i++) S.scheduler->run(0);
    return;
  }

  // vtype=7: NotarizationObserved injection — publish NotarizationObserved directly into bus.
  // ConsensusImpl::process_notarization_observed receives it → sets slot->state->notar_cert →
  // calls try_vote_final: if voted_notar == notar_cert (ConsensusImpl already voted notarize
  // on the same CandidateId), emits FinalizeVote via BroadcastVote.
  // Most useful after vtype=3 Propose sequence that made ConsensusImpl emit NotarizeVote.
  // Also covers: timeout_slot_ advancement, alarm_timestamp() update paths in ConsensusImpl.
  // CandidateResolver::handle(NotarizationObserved) also fires — resolver cleanup path.
  // src_idx reused as signature count (1..N_VALIDATORS-1) for the dummy NotarCert.
  if (vote_type == 7) {
    CandidateId cand_id{.slot = slot, .hash = S.cand_hashes[cand_seed]};
    NotarizeVote notar_vote{cand_id};
    std::vector<NotarCert::VoteSignature> sigs;
    auto n_sigs = static_cast<uint8_t>(((src_idx - 1) % (N_VALIDATORS - 1)) + 1);
    for (uint8_t i = 1; i <= n_sigs; i++) {
      sigs.push_back(NotarCert::VoteSignature{PeerValidatorId{i}, td::BufferSlice(64)});
    }
    auto cert = td::make_ref<NotarCert>(notar_vote, std::move(sigs));
    auto ev = std::make_shared<NotarizationObserved>(cand_id, std::move(cert));
    S.scheduler->run_in_context([&] { S.bus.publish(ev); });
    for (int i = 0; i < DRAIN_ROUNDS; i++) S.scheduler->run(0);
    return;
  }

  // vtype=8: FinalizationObserved injection — publish FinalizationObserved directly into bus.
  // Symmetric counterpart of vtype=7 (NotarizationObserved). Directly injects FinalCert
  // bypassing pool.cpp's quorum-building path. Tests ConsensusImpl finalization handling,
  // FinalCert acceptance in pool.cpp, and cross-slot invariants when finalization arrives
  // out of order or without a prior NotarCert.
  // src_idx reused as signature count (1..N_VALIDATORS-1) for the dummy FinalCert.
  if (vote_type == 8) {
    CandidateId cand_id{.slot = slot, .hash = S.cand_hashes[cand_seed]};
    FinalizeVote final_vote{cand_id};
    std::vector<FinalCert::VoteSignature> sigs;
    auto n_sigs = static_cast<uint8_t>(((src_idx - 1) % (N_VALIDATORS - 1)) + 1);
    for (uint8_t i = 1; i <= n_sigs; i++) {
      sigs.push_back(FinalCert::VoteSignature{PeerValidatorId{i}, td::BufferSlice(64)});
    }
    auto cert = td::make_ref<FinalCert>(final_vote, std::move(sigs));
    auto ev = std::make_shared<FinalizationObserved>(FinalizationObserved{cand_id, std::move(cert)});
    S.scheduler->run_in_context([&] { S.bus.publish(ev); });
    for (int i = 0; i < DRAIN_ROUNDS; i++) S.scheduler->run(0);
    return;
  }

  // vtype=9: Threshold-burst split — deterministically creates split notarize_weight state.
  // Injects WEIGHT_THRESHOLD-1 NotarizeVotes for cand_seed (cand_a) from validators
  // 1..threshold-1, then 1 NotarizeVote for (cand_seed+1)%N_CAND_SEEDS (cand_b) from
  // validator threshold. Result: notarize_weight[cand_a]=threshold-1, notarize_weight[cand_b]=1,
  // neither reaching quorum — tests Byzantine candidate flooding and notarize_weight map
  // split state. src_idx unused (deterministic validator selection).
  if (vote_type == 9) {
    uint8_t cand_b = static_cast<uint8_t>((cand_seed + 1) % N_CAND_SEEDS);
    // Inject threshold-1 votes for cand_a from validators 1..threshold-1
    for (size_t v = 1; v < WEIGHT_THRESHOLD; v++) {
      auto vtl_a = create_tl_object<ton_api::consensus_simplex_notarizeVote>(
          create_tl_object<ton_api::consensus_candidateId>(
              static_cast<int32_t>(slot), S.cand_hashes[cand_seed]));
      auto svtl_a = create_tl_object<ton_api::consensus_simplex_vote>(
          std::move(vtl_a), td::BufferSlice(64));
      auto bytes_a = serialize_tl_object(svtl_a, true);
      auto msg_a = std::make_shared<IncomingProtocolMessage>(
          PeerValidatorId{static_cast<uint8_t>(v)}, ProtocolMessage{std::move(bytes_a)});
      S.scheduler->run_in_context([&] { S.bus.publish(msg_a); });
      for (int i = 0; i < DRAIN_ROUNDS; i++) S.scheduler->run(0);
    }
    // Inject 1 vote for cand_b from validator threshold (split below quorum)
    auto vtl_b = create_tl_object<ton_api::consensus_simplex_notarizeVote>(
        create_tl_object<ton_api::consensus_candidateId>(
            static_cast<int32_t>(slot), S.cand_hashes[cand_b]));
    auto svtl_b = create_tl_object<ton_api::consensus_simplex_vote>(
        std::move(vtl_b), td::BufferSlice(64));
    auto bytes_b = serialize_tl_object(svtl_b, true);
    auto msg_b = std::make_shared<IncomingProtocolMessage>(
        PeerValidatorId{static_cast<uint8_t>(WEIGHT_THRESHOLD)}, ProtocolMessage{std::move(bytes_b)});
    S.scheduler->run_in_context([&] { S.bus.publish(msg_b); });
    for (int i = 0; i < DRAIN_ROUNDS; i++) S.scheduler->run(0);
    g_state_counters[134]++;  // GC_THRESHOLD_SPLIT
    return;
  }

  // vtype=10: SkipVote flood — deterministic SkipCert formation for single slot.
  // Symmetric to vtype=9 (NotarizeVote threshold-burst) but for SkipVotes: ensures
  // skip_weight[slot] reaches quorum, forming a SkipCert unconditionally.
  // Tests is_skipped() state and cross-cert invariants (NotarCert ∧ SkipCert ⇒ ⊥).
  if (vote_type == 10) {
    skip_flood_slot(slot);
    g_state_counters[135]++;  // GC_SKIP_FLOOD
    return;
  }

  // vtype=15: Window-spanning skip — skips all slots in the window containing `slot`.
  // Computes window start = (slot / SLOTS_PER_WINDOW) * SLOTS_PER_WINDOW, then calls
  // skip_flood_slot for each slot in [window_start, window_start + SLOTS_PER_WINDOW).
  // All slots in the window get SkipCerts → pool calls advance_present() for each →
  // LeaderWindowObserved fires, triggering ConsensusImpl::start_generation() for the
  // next window. Tests window-transition code paths not reachable by single-slot floods.
  if (vote_type == 15) {
    uint8_t window_start = static_cast<uint8_t>((slot / SLOTS_PER_WINDOW) * SLOTS_PER_WINDOW);
    for (uint8_t s = window_start;
         s < window_start + static_cast<uint8_t>(SLOTS_PER_WINDOW) && s <= MAX_SLOT; s++) {
      skip_flood_slot(s);
    }
    g_state_counters[146]++;  // GC_WINDOW_SPANNING_SKIP
    return;
  }

  // vtype=11: Multi-slot chain attack — structured sequence across adjacent slots.
  // For slot s:   injects WEIGHT_THRESHOLD-1 NotarizeVotes (sub-threshold, no cert formed).
  // For slot s+1: injects 1 SkipVote from src_idx.
  // For slot s+2: injects 1 NotarizeVote for cand_seed from src_idx.
  // Simulates a real scenario: slot s borderline, s+1 skipped, s+2 starts notarize.
  // Tests cross-slot invariants and vote-weight split interactions.
  if (vote_type == 11) {
    // Slot s: sub-threshold NotarizeVotes from validators 1..threshold-1
    for (size_t v = 1; v < WEIGHT_THRESHOLD; v++) {
      auto vtl = create_tl_object<ton_api::consensus_simplex_notarizeVote>(
          create_tl_object<ton_api::consensus_candidateId>(
              static_cast<int32_t>(slot), S.cand_hashes[cand_seed]));
      auto svtl = create_tl_object<ton_api::consensus_simplex_vote>(
          std::move(vtl), td::BufferSlice(64));
      auto bytes = serialize_tl_object(svtl, true);
      auto msg = std::make_shared<IncomingProtocolMessage>(
          PeerValidatorId{static_cast<uint8_t>(v)}, ProtocolMessage{std::move(bytes)});
      S.scheduler->run_in_context([&] { S.bus.publish(msg); });
      for (int i = 0; i < DRAIN_ROUNDS; i++) S.scheduler->run(0);
    }
    // Slot s+1: single SkipVote from src_idx
    if (slot + 1 <= MAX_SLOT) {
      auto vtl1 = create_tl_object<ton_api::consensus_simplex_skipVote>(
          static_cast<int32_t>(slot + 1));
      auto svtl1 = create_tl_object<ton_api::consensus_simplex_vote>(
          std::move(vtl1), td::BufferSlice(64));
      auto bytes1 = serialize_tl_object(svtl1, true);
      auto msg1 = std::make_shared<IncomingProtocolMessage>(
          PeerValidatorId{src_idx}, ProtocolMessage{std::move(bytes1)});
      S.scheduler->run_in_context([&] { S.bus.publish(msg1); });
      for (int i = 0; i < DRAIN_ROUNDS; i++) S.scheduler->run(0);
    }
    // Slot s+2: single NotarizeVote from src_idx
    if (slot + 2 <= MAX_SLOT) {
      auto vtl2 = create_tl_object<ton_api::consensus_simplex_notarizeVote>(
          create_tl_object<ton_api::consensus_candidateId>(
              static_cast<int32_t>(slot + 2), S.cand_hashes[cand_seed]));
      auto svtl2 = create_tl_object<ton_api::consensus_simplex_vote>(
          std::move(vtl2), td::BufferSlice(64));
      auto bytes2 = serialize_tl_object(svtl2, true);
      auto msg2 = std::make_shared<IncomingProtocolMessage>(
          PeerValidatorId{src_idx}, ProtocolMessage{std::move(bytes2)});
      S.scheduler->run_in_context([&] { S.bus.publish(msg2); });
      for (int i = 0; i < DRAIN_ROUNDS; i++) S.scheduler->run(0);
    }
    g_state_counters[136]++;  // GC_MULTI_SLOT
    return;
  }

  // vtype=12: FinalizeVote flood — deterministic FinalCert formation.
  // Injects WEIGHT_THRESHOLD FinalizeVotes for `slot` from validators 1..WEIGHT_THRESHOLD.
  // Symmetric to vtype=10 (SkipVote flood) but for FinalizeVotes: ensures finalize_weight
  // reaches quorum, forming a FinalCert unconditionally. Tests #skip-finalize
  // (FinalCert on SkipCert'd slot) and cross-cert invariants.
  if (vote_type == 12) {
    for (size_t v = 1; v <= WEIGHT_THRESHOLD; v++) {
      auto vtl = create_tl_object<ton_api::consensus_simplex_finalizeVote>(
          create_tl_object<ton_api::consensus_candidateId>(
              static_cast<int32_t>(slot), S.cand_hashes[cand_seed]));
      auto svtl = create_tl_object<ton_api::consensus_simplex_vote>(
          std::move(vtl), td::BufferSlice(64));
      auto bytes = serialize_tl_object(svtl, true);
      auto msg = std::make_shared<IncomingProtocolMessage>(
          PeerValidatorId{static_cast<uint8_t>(v)}, ProtocolMessage{std::move(bytes)});
      S.scheduler->run_in_context([&] { S.bus.publish(msg); });
      for (int i = 0; i < DRAIN_ROUNDS; i++) S.scheduler->run(0);
    }
    g_state_counters[141]++;  // GC_FINALIZE_FLOOD
    return;
  }

  // vtype=13: Byzantine double-vote — same validator casts conflicting votes for same slot.
  // Injects NotarizeVote{slot, cand_seed} then SkipVote{slot} from the same src_idx.
  // Tests MisbehaviorReport detection, tolerate_conflicts path, and whether the pool
  // properly handles a validator voting twice for the same slot (equivocation).
  // slot%2 selects the conflict order: 0=Notarize first, 1=Skip first.
  if (vote_type == 13) {
    auto make_vote_msg = [&](tl_object_ptr<ton_api::consensus_simplex_UnsignedVote> v_tl) {
      auto svtl = create_tl_object<ton_api::consensus_simplex_vote>(
          std::move(v_tl), td::BufferSlice(64));
      auto bytes = serialize_tl_object(svtl, true);
      auto msg = std::make_shared<IncomingProtocolMessage>(
          PeerValidatorId{src_idx}, ProtocolMessage{std::move(bytes)});
      S.scheduler->run_in_context([&] { S.bus.publish(msg); });
      for (int i = 0; i < DRAIN_ROUNDS; i++) S.scheduler->run(0);
    };
    auto notar_tl = create_tl_object<ton_api::consensus_simplex_notarizeVote>(
        create_tl_object<ton_api::consensus_candidateId>(
            static_cast<int32_t>(slot), S.cand_hashes[cand_seed]));
    auto skip_tl = create_tl_object<ton_api::consensus_simplex_skipVote>(
        static_cast<int32_t>(slot));
    if (slot % 2 == 0) {
      make_vote_msg(std::move(notar_tl));
      make_vote_msg(std::move(skip_tl));
    } else {
      make_vote_msg(std::move(skip_tl));
      make_vote_msg(std::move(notar_tl));
    }
    g_state_counters[142]++;  // GC_BYZANTINE_DOUBLE
    return;
  }

  // vtype=14: LeaderWindowObserved direct injection — advances the consensus window.
  // Publishes LeaderWindowObserved{start_slot=slot, base} directly to the bus,
  // triggering ConsensusImpl::handle(LeaderWindowObserved) → start_generation() →
  // new leader window starts, alarm is reset. Tests window boundary handling,
  // spurious window advance, and interactions with in-progress slot state.
  // base = nullopt for slot=0, CandidateId{slot-1, cand_seed} for slot>0.
  if (vote_type == 14) {
    ParentId base = slot > 0
        ? std::make_optional(CandidateId{.slot = static_cast<td::uint32>(slot - 1),
                                         .hash = S.cand_hashes[cand_seed]})
        : std::nullopt;
    auto ev = std::make_shared<LeaderWindowObserved>(LeaderWindowObserved{
        .start_slot = slot, .base = base});
    S.scheduler->run_in_context([&] { S.bus.publish(ev); });
    for (int i = 0; i < DRAIN_ROUNDS; i++) S.scheduler->run(0);
    g_state_counters[143]++;  // GC_LEADER_WINDOW_INJECT
    return;
  }

  tl_object_ptr<ton_api::consensus_simplex_UnsignedVote> vote_tl;
  if (vote_type == 0) {
    vote_tl = create_tl_object<ton_api::consensus_simplex_notarizeVote>(
        create_tl_object<ton_api::consensus_candidateId>(
            static_cast<int32_t>(slot), S.cand_hashes[cand_seed]));
  } else if (vote_type == 1) {
    vote_tl = create_tl_object<ton_api::consensus_simplex_skipVote>(
        static_cast<int32_t>(slot));
  } else {
    vote_tl = create_tl_object<ton_api::consensus_simplex_finalizeVote>(
        create_tl_object<ton_api::consensus_candidateId>(
            static_cast<int32_t>(slot), S.cand_hashes[cand_seed]));
  }

  auto signed_vote_tl = create_tl_object<ton_api::consensus_simplex_vote>(
      std::move(vote_tl), td::BufferSlice(64));
  auto msg_bytes = serialize_tl_object(signed_vote_tl, true);
  auto msg = std::make_shared<IncomingProtocolMessage>(
      PeerValidatorId{src_idx}, ProtocolMessage{std::move(msg_bytes)});

  S.scheduler->run_in_context([&] { S.bus.publish(msg); });
  for (int i = 0; i < DRAIN_ROUNDS; i++) S.scheduler->run(0);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  ++g_invocation;
  if (size < 4) return 0;

  // Full reset: destroy and recreate the scheduler to avoid scheduler IO-queue
  // accumulation across runs. After 1000+ runs, unprocessed messages from
  // destroyed actors accumulate in the scheduler's queue. When new actors are
  // created with recycled IDs, stale messages can be misdelivered. Recreating
  // the scheduler gives a completely clean queue every run.
  //
  // Before deleting, publish StopRequested so PoolImpl::tear_down() resolves all
  // pending WaitForParent promises via set_error(cancelled). Without this,
  // slot>0 Propose injections leave suspended coroutines that cause SEGV in
  // HazardPointers when the runtime is destroyed.
  // Teardown: stop current bus, drain, then restart cleanly WITHOUT deleting
  // the scheduler — destroying the scheduler while actors are alive triggers
  // SharedObjectPool LOG_CHECK. Instead, reuse the existing scheduler and
  // create a fresh bus/runtime/db on top of it (mirrors crash_and_restart).
  if (g_state && g_state->runtime) {
    g_state->scheduler->run_in_context([&] {
      g_state->bus.publish(std::make_shared<StopRequested>());
    });
    {
      int extra = 0;
      for (int i = 0; i < DRAIN_CRASH_ROUNDS; i++) {
        g_state->scheduler->run(0);
        if (simplex::g_pending_requests_count.load() == 0) {
          if (++extra >= EXTRA_DRAIN_AFTER_TEARDOWN) break;
        } else {
          extra = 0;
        }
      }
    }
    // Release keyring and bus handles so their actors receive stop()/destroy.
    g_state->scheduler->run_in_context([&] {
      g_state->keyring = {};
    });
    g_state->bus = {};
    for (int i = 0; i < DRAIN_CRASH_ROUNDS; i++) {
      g_state->scheduler->run(0);
      if (simplex::g_pending_requests_count.load() == 0) break;
    }
    // Force-clear the actor pool: BusListeningActors hold
    // shared_ptr<BusTreeNode>→shared_ptr<Runtime>, so runtime.reset() alone
    // cannot drop the ref count to 0 and no destroy messages are ever sent.
    // ActorInfoCreator::clear() calls dec_ref() on every live ActorInfo,
    // breaking the ref cycle — slots return to free_queue, stopping linear
    // RSS growth (~65 KB/iter) that caused OOM in fork-mode workers.
    g_state->scheduler->run_in_context([] {
      td::actor::core::SchedulerContext::get().get_actor_info_creator().clear();
    });
    g_state->runtime.reset();
    for (int i = 0; i < DRAIN_CRASH_ROUNDS; i++) {
      g_state->scheduler->run(0);
      if (simplex::g_pending_requests_count.load() == 0) break;
    }
  }
  // Reinitialize state in-place (reuse scheduler, create new keyring+runtime+bus).
  if (!g_state) g_state = new FuzzState();
  auto& S = *g_state;

  S.session_id = td::Bits256{};
  S.session_id.as_array()[0] = 0x42;
  for (size_t i = 0; i < N_CAND_SEEDS; i++) {
    S.cand_hashes[i] = td::Bits256{};
    S.cand_hashes[i].as_array()[0] = static_cast<uint8_t>(i + 1);
  }
  if (!S.scheduler) {
    S.scheduler = std::make_unique<td::actor::Scheduler>(
        std::vector<td::actor::Scheduler::NodeInfo>{{0}}, /*skip_timeouts=*/true);
  }
  S.scheduler->run_in_context([&] {
    S.keyring = td::actor::create_actor<MockKeyring>(
        td::actor::ActorOptions{}.with_name("MockKeyring"));
  });

  ++g_run_id;
  std::memset(g_state_counters, 0, STATE_COUNTER_BYTES);
  g_post_crash_phase = false;
  g_our_notar_vote.clear();
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
  ton::validator::consensus::simplex::g_conflict_tolerated_count.store(0);
#endif

  configure_and_start_bus(S, std::make_unique<MockDb>());

  g_safety_active = true;
  FuzzedDataProvider fdp(data, size);

  // Fuzz input layout (Phase 9 — n_windows, n_post_crashes, vtype=15):
  //   n_pre           : uint8 (0..15)  — messages before crashes
  //   do_perm         : bool           — if true, shuffle n_pre messages before injection
  //   perm_seed       : uint8          — LCG seed for Fisher-Yates (only if do_perm)
  //   n_windows       : uint8 (0..2)   — complete windows to skip before crash loop
  //   n_crashes       : uint8 (0..2)   — sequential crash+restart cycles
  //   n_mid_ticks     : uint8 (0..2)   — alarm ticks between pre-msgs and crash loop
  //   n_post          : uint8 (0..7)   — messages after last crash
  //   do_perm_post    : bool           — if true, shuffle n_post messages before injection
  //   perm_post_seed  : uint8          — LCG seed for post-shuffle (only if do_perm_post)
  //   n_post_crashes  : uint8 (0..1)   — extra crash cycle after post-msgs
  //   n_ticks         : uint8 (0..3)   — alarm ticks (each fires run(15.0))
  //   n_post_tick     : uint8 (0..4)   — messages after all ticks
  //   per message: src_idx, vote_type (0..15), slot, cand_seed
  //   per crash (inside loop): n_lose, lose_mode(0..4), n_inter(0..4)+msgs, n_inter_ticks(0..2)
  //   per post-crash (inside n_post_crashes loop): n_lose_pc, lose_mode_pc(0..4)
  //
  // Permutation rationale: delivery order of consensus messages should not affect
  // safety. Shuffling pre/post-crash messages tests order-dependent state bugs, including
  // ConflictTolerated during bootstrap replay (#conflict-tolerated).
  uint8_t  n_pre          = fdp.ConsumeIntegralInRange<uint8_t>(0, 15);
  bool     do_perm        = fdp.ConsumeBool();
  uint32_t perm_lcg       = do_perm ? fdp.ConsumeIntegral<uint8_t>() : 0u;
  uint8_t  n_windows      = fdp.ConsumeIntegralInRange<uint8_t>(0, 2);
  uint8_t  n_crashes      = fdp.ConsumeIntegralInRange<uint8_t>(0, 2);
  uint8_t  n_mid_ticks    = fdp.ConsumeIntegralInRange<uint8_t>(0, 2);
  uint8_t  n_post         = fdp.ConsumeIntegralInRange<uint8_t>(0, 7);
  bool     do_perm_post   = fdp.ConsumeBool();
  uint32_t perm_post_lcg  = do_perm_post ? fdp.ConsumeIntegral<uint8_t>() : 0u;
  uint8_t  n_post_crashes = fdp.ConsumeIntegralInRange<uint8_t>(0, 1);
  uint8_t  n_ticks        = fdp.ConsumeIntegralInRange<uint8_t>(0, 3);
  uint8_t  n_post_tick    = fdp.ConsumeIntegralInRange<uint8_t>(0, 4);

  // Read all pre-crash messages upfront so we can permute them.
  std::vector<MsgSpec> pre_msgs;
  pre_msgs.reserve(n_pre);
  for (uint8_t m = 0; m < n_pre; m++) {
    if (auto spec = read_msg_spec(fdp)) pre_msgs.push_back(std::move(*spec));
    else break;
  }

  // Optionally permute with Fisher-Yates (LCG PRNG seeded by perm_lcg).
  if (do_perm && pre_msgs.size() > 1) {
    for (size_t i = pre_msgs.size() - 1; i > 0; i--) {
      perm_lcg = perm_lcg * 1664525u + 1013904223u;  // Numerical Recipes LCG
      size_t j = perm_lcg % (i + 1);
      std::swap(pre_msgs[i], pre_msgs[j]);
    }
  }

  for (auto& spec : pre_msgs) inject_from_spec(spec);

  // Window-skip phase: skip `n_windows` complete leader windows before the crash loop.
  // Window i covers slots [i*SLOTS_PER_WINDOW, (i+1)*SLOTS_PER_WINDOW). Skipping all
  // slots in a window forces pool::advance_present() through the full window, triggering
  // LeaderWindowObserved → ConsensusImpl::start_generation() for window i+1.
  // This opens window-transition code paths (new leader, new alarm_timestamp, new base slot)
  // that are otherwise only reached after many messages in natural fuzzing.
  for (uint8_t w = 0; w < n_windows; w++) {
    for (uint8_t s = static_cast<uint8_t>(w * SLOTS_PER_WINDOW);
         s < static_cast<uint8_t>((w + 1) * SLOTS_PER_WINDOW) && s <= MAX_SLOT; s++) {
      skip_flood_slot(s);
    }
    g_state_counters[147]++;  // GC_N_WINDOWS
  }

  // Mid-ticks: fire standstill alarm between pre-msgs and crash loop.
  // Tests alarm→SkipVote→SkipCert state reached BEFORE any crash, then crash
  // replays over already-skipped slots. Distinct from n_ticks (which fires after
  // all crashes and post-msgs). n_mid_ticks=0 preserves Phase 6 behavior.
  {
    auto& S_mid = *g_state;
    for (uint8_t t = 0; t < n_mid_ticks; t++) {
      S_mid.scheduler->run(15.0);
      for (int i = 0; i < DRAIN_ROUNDS; i++) S_mid.scheduler->run(0);
      g_state_counters[137]++;  // GC_MID_TICK
    }
  }

  // Sequential crash+restart cycles — each with its own n_lose, lose_first, and
  // n_inter inter-crash messages consumed from fdp.
  // lose_first: true=lose first N WAL writes (early-session corruption), false=last N.
  // n_inter: messages injected after crash i completes (before crash i+1 or post phase).
  // Tests WAL corruption accumulation across multiple restarts and inter-restart vote injection.
  for (uint8_t c = 0; c < n_crashes; c++) {
    uint8_t n_lose_c   = fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_LOSE_WRITES);
    uint8_t lose_mode  = fdp.ConsumeIntegralInRange<uint8_t>(0, 4);
    // lose_mode: 0=last N, 1=first N, 2=stride-2, 3=stride-3, 4=stride-4
    crash_and_restart(*g_state, n_lose_c, lose_mode);
    if (lose_mode == 1) g_state_counters[139]++;  // GC_FIRST_N_CORRUPTION
    if (lose_mode >= 2) g_state_counters[145]++;  // GC_STRIDE_CORRUPTION
    if (c > 0) g_state_counters[132]++;  // GC_MULTI_CRASHED
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    // #conflict-tolerated: bootstrap replay found conflicting local votes in DB.
    // This should NEVER happen for an honest validator — it means the node voted
    // twice for the same slot (safety violation). Trap after each restart drain.
    if (ton::validator::consensus::simplex::g_conflict_tolerated_count.load() > 0) {
      __builtin_trap();  // #conflict-tolerated: local validator has conflicting DB votes after restart
    }
#endif
    // Inter-crash messages: votes arriving after crash i but before crash i+1 (or post phase).
    uint8_t n_inter_c = fdp.ConsumeIntegralInRange<uint8_t>(0, 4);
    for (uint8_t m = 0; m < n_inter_c; m++) {
      inject_vote(fdp);
      g_state_counters[138]++;  // GC_INTER_CRASH_MSG
    }
    // Inter-crash ticks: alarm fires between restarts — SkipVote broadcast post-restart
    // then another crash occurs. Tests SkipCert-in-progress state at crash time.
    uint8_t n_inter_ticks_c = fdp.ConsumeIntegralInRange<uint8_t>(0, 2);
    {
      auto& S_inter = *g_state;
      for (uint8_t t = 0; t < n_inter_ticks_c; t++) {
        S_inter.scheduler->run(15.0);
        for (int i = 0; i < DRAIN_ROUNDS; i++) S_inter.scheduler->run(0);
        g_state_counters[144]++;  // GC_INTER_CRASH_TICK
      }
    }
  }

  // Read all post-crash messages upfront so we can optionally permute them.
  std::vector<MsgSpec> post_msgs;
  post_msgs.reserve(n_post);
  for (uint8_t m = 0; m < n_post; m++) {
    if (auto spec = read_msg_spec(fdp)) post_msgs.push_back(std::move(*spec));
    else break;
  }
  // Optionally shuffle post-crash messages (Fisher-Yates, LCG seeded by perm_post_lcg).
  // Tests whether message ordering after restart affects safety — symmetry to do_perm.
  if (do_perm_post && post_msgs.size() > 1) {
    for (size_t i = post_msgs.size() - 1; i > 0; i--) {
      perm_post_lcg = perm_post_lcg * 1664525u + 1013904223u;
      size_t j = perm_post_lcg % (i + 1);
      std::swap(post_msgs[i], post_msgs[j]);
    }
  }
  for (auto& spec : post_msgs) {
    inject_from_spec(spec);
    if (do_perm_post) g_state_counters[140]++;  // GC_PERM_POST_MSG
  }

  // Post-crash phase: additional crash cycle AFTER post-msgs, before n_ticks.
  // Tests state that has gone through a full round of pre-msgs → crashes → post-msgs
  // and then crashes again. Key scenario: validator accumulated votes in post phase
  // (possibly formed a cert), then crashes — bootstrap sees a richer WAL than pre-crash.
  for (uint8_t c = 0; c < n_post_crashes; c++) {
    uint8_t n_lose_pc  = fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_LOSE_WRITES);
    uint8_t lose_mode_pc = fdp.ConsumeIntegralInRange<uint8_t>(0, 4);
    crash_and_restart(*g_state, n_lose_pc, lose_mode_pc);
    g_state_counters[148]++;  // GC_POST_CRASHED
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    if (ton::validator::consensus::simplex::g_conflict_tolerated_count.load() > 0) {
      __builtin_trap();  // #conflict-tolerated after post-crash restart
    }
#endif
  }

  // Multi-tick: fire standstill alarm n_ticks times. Each run(15.0) triggers
  // Time::jump_in_future() so the next run(0) fires all pending alarm_timestamp()
  // callbacks. Multiple ticks test repeated alarm() firings and slot advancement
  // through cascading SkipVotes across windows.
  auto& S_final = *g_state;
  for (uint8_t t = 0; t < n_ticks; t++) {
    S_final.scheduler->run(15.0);
    for (int i = 0; i < DRAIN_ROUNDS; i++) S_final.scheduler->run(0);
  }

  // Post-tick message injection: votes arriving AFTER alarm has fired.
  // Key scenario: NotarizeVote arrives after SkipVote was cast → conflict.
  // Also: FinalizeVote on SkipCert'd slot, FinalizeVote without prior NotarCert.
  for (uint8_t m = 0; m < n_post_tick; m++) {
    inject_vote(fdp);
    g_state_counters[133]++;  // GC_POST_TICK_MSG
  }

  // Final drain: flush all pending events (e.g. SkipCert from a just-reached
  // quorum). Safety checks remain active during this drain — if a violation
  // fires here, it genuinely belongs to this run.
  for (int i = 0; i < DRAIN_CRASH_ROUNDS; i++) S_final.scheduler->run(0);
  g_safety_active = false;

  // Liveness guidance: if any ticks fired + windows advanced but NO cert was issued
  // this run → protocol made no progress under time pressure. Not a hard trap (too
  // many legitimate reasons: not enough votes injected), but signals the fuzzer to
  // explore this region more via vector guidance (REF_LIVENESS).
  if (n_ticks > 0 && g_state_counters[129] > 0) {
    bool any_cert = false;
    for (auto& [slot, pair] : g_notar_by_slot) { if (pair.first == g_run_id) { any_cert = true; break; } }
    if (!any_cert) for (auto& [slot, pair] : g_final_by_slot) { if (pair.first == g_run_id) { any_cert = true; break; } }
    if (!any_cert) g_state_counters[131] = std::min(255, (int)g_state_counters[131] + 1);
  }

  // Phase 3 Step 3: emit cosine similarity scores toward reference danger states.
  emit_vector_guidance();

  return 0;
}
