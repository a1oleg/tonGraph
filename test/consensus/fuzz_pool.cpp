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
 * Fuzz input layout (FuzzedDataProvider):
 *   n_messages  : uint8  (0..15)
 *   do_crash    : bool
 *   n_lose      : uint8  (0..MAX_LOSE_WRITES)
 *   per message:
 *     src_idx   : uint8  (0..N_VALIDATORS-1)
 *     vote_type : uint8  (0=notarize, 1=skip, 2=finalize)
 *     slot      : uint8  (0..MAX_SLOT)
 *     cand_seed : uint8  (0..N_CAND_SEEDS-1)
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
#include "td/actor/coro_utils.h"
#include "tl-utils/common-utils.hpp"
#include "ton/ton-types.h"
#include "validator/interfaces/validator-manager.h"

#include "simulation/GraphLogger.h"
#include "td/utils/logging.h"

#include <cmath>

// ─────────────────────────────────────────────────────────────────────────────

static constexpr size_t N_VALIDATORS = 4;
static constexpr uint8_t MAX_SLOT = 15;
static constexpr uint8_t N_CAND_SEEDS = 4;
static constexpr uint8_t MAX_LOSE_WRITES = 8;
static constexpr int DRAIN_ROUNDS = 20;
static constexpr int DRAIN_CRASH_ROUNDS = 200;

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

static constexpr int STATE_COUNTER_BYTES = 136;
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
//   4=SE_POST_CRASH 5=SE_BOTH_NS   6=SE_CERT_SKIP  7=reserved

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
  255.f,  // SE_CERT_SKIP:   skip cert also present → dual-cert
    0.f,  // reserved
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

// Emit similarity scores for all three reference vectors across all slots.
// Channel byte: 0xE0 | (ref_idx << 4) | slot — unique per (ref, slot) pair.
static void emit_vector_guidance() {
  const float* refs[3] = {REF_ALARM_SKIP, REF_AMNESIA, REF_DUAL_CERT};
  for (int r = 0; r < 3; r++) {
    for (int slot = 0; slot < 16; slot++) {
      float sim = cosine_sim_slot(refs[r], &g_state_counters[slot * SE_STRIDE]);
      auto sim_byte = static_cast<uint8_t>(sim * 255.f);
      // Channel: 0xA0 = alarm-skip family, 0xB0 = amnesia family, 0xC0 = dual-cert
      auto channel  = static_cast<uint8_t>(0xA0 + r * 0x10 + slot);
      __sanitizer_cov_trace_cmp1(channel, sim_byte);
    }
  }
}

enum SlotEvent : int {
  SE_NOTAR_VOTE = 0,
  SE_SKIP_VOTE  = 1,
  SE_FINAL_VOTE = 2,
  SE_NOTAR_CERT = 3,
  SE_POST_CRASH = 4,
  SE_BOTH_NS    = 5,
  SE_CERT_SKIP  = 6,
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

  std::vector<std::pair<td::BufferSlice, td::BufferSlice>> get_by_prefix(td::uint32) const override {
    return {};
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
static std::map<td::uint32, td::Bits256> g_notar_by_slot;
static std::map<td::uint32, td::Bits256> g_skip_by_slot;

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
    // Safety: NotarCert + SkipCert on same slot
    if (g_skip_by_slot.count(slot)) {
      __builtin_trap();
    }
    // Safety: two different NotarCerts on same slot
    auto [it, inserted] = g_notar_by_slot.emplace(slot, hash);
    if (!inserted && it->second != hash) {
      __builtin_trap();
    }

    // Step 4: state counter
    slot_event(static_cast<int32_t>(slot), SE_NOTAR_CERT);
    if (g_post_crash_phase) g_state_counters[130]++;
  }

  template <>
  void handle(FuzzBusHandle, std::shared_ptr<const FinalizationObserved>) {}

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
        g_skip_by_slot.emplace(slot, td::Bits256{});
        slot_event(static_cast<int32_t>(slot), SE_CERT_SKIP);
        // Safety: SkipCert on a slot that already has a NotarCert → violation
        if (g_notar_by_slot.count(slot)) {
          __builtin_trap();
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
        if (nv->id_) slot_event(nv->id_->slot_, SE_NOTAR_VOTE);
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

  template <>
  td::actor::Task<ResolveState::Result> process(FuzzBusHandle, std::shared_ptr<ResolveState>) {
    co_return td::Status::Error("mock");
  }

  template <>
  td::actor::Task<ResolveCandidate::Result> process(FuzzBusHandle, std::shared_ptr<ResolveCandidate>) {
    co_return td::Status::Error("mock");
  }

  template <>
  td::actor::Task<StoreCandidate::ReturnType> process(FuzzBusHandle, std::shared_ptr<StoreCandidate>) {
    co_return td::Unit{};
  }

  template <>
  td::actor::Task<ValidateCandidateResult> process(FuzzBusHandle, std::shared_ptr<ValidationRequest>) {
    co_return CandidateReject{"mock", {}};
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

static void crash_and_restart(FuzzState& S, size_t n_lose) {
  S.db_raw->crash_losing_last_n(n_lose);
  auto recovered_db = S.db_raw->clone();

  S.scheduler->run_in_context([&] {
    S.bus.publish(std::make_shared<StopRequested>());
  });
  for (int i = 0; i < DRAIN_CRASH_ROUNDS; i++) {
    S.scheduler->run(0);
  }

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
static void inject_vote(FuzzedDataProvider& fdp) {
  if (fdp.remaining_bytes() < 4) return;
  auto& S = *g_state;

  auto src_idx   = fdp.ConsumeIntegralInRange<uint8_t>(0, N_VALIDATORS - 1);
  auto vote_type = fdp.ConsumeIntegralInRange<uint8_t>(0, 2);
  auto slot      = fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_SLOT);
  auto cand_seed = fdp.ConsumeIntegralInRange<uint8_t>(0, N_CAND_SEEDS - 1);
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
  if (size < 4) return 0;

  // Reset state-vector counters for this run.
  std::memset(g_state_counters, 0, STATE_COUNTER_BYTES);
  g_post_crash_phase = false;

  FuzzedDataProvider fdp(data, size);

  // Fuzz input layout (Phase 4 Step 0):
  //   n_pre    : uint8 (0..15) — messages before crash
  //             raised from 7: slots_per_leader_window=4 requires ≥12 pre-crash
  //             votes (4 slots × 3 validators) to advance first_nonannounced_window
  //             beyond 0, enabling ConsensusImpl::start_up() SkipVote broadcast.
  //   do_crash : bool
  //   n_lose   : uint8 (0..MAX_LOSE_WRITES)
  //   n_post   : uint8 (0..7)  — messages after crash (enables alarm-skip quorum)
  //   per message: src_idx, vote_type, slot, cand_seed
  uint8_t n_pre    = fdp.ConsumeIntegralInRange<uint8_t>(0, 15);
  bool    do_crash = fdp.ConsumeBool();
  uint8_t n_lose   = fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_LOSE_WRITES);
  uint8_t n_post   = fdp.ConsumeIntegralInRange<uint8_t>(0, 7);
  for (uint8_t m = 0; m < n_pre; m++)  inject_vote(fdp);

  if (do_crash) crash_and_restart(*g_state, n_lose);

  for (uint8_t m = 0; m < n_post; m++) inject_vote(fdp);

  // Phase 3 Step 3: emit cosine similarity scores toward reference danger states.
  emit_vector_guidance();

  return 0;
}
