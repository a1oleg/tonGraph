/*
 * Copyright (c) 2026, TON CORE TECHNOLOGIES CO. L.L.C
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 *
 * Standalone PoC for the amnesia vulnerability (#amnesia-gap → #amnesia).
 *
 * Root cause (db.cpp:57-94):
 *   ConsensusImpl calls BroadcastVote(NotarizeVote) which is BROADCAST on the
 *   network BEFORE DbImpl's co_await db->set() completes. If the node crashes
 *   in that async window, the vote is lost from DB.
 *
 * After restart (start_up in consensus.cpp:48-81):
 *   bootstrap_votes loaded from DB — the lost vote is absent.
 *   ConsensusImpl's slot.state->voted_notar = nullopt for that slot.
 *
 * Exploitation:
 *   A leader sends CandidateReceived{cand_B, slot=0} post-restart.
 *   ConsensusImpl, not knowing it voted for cand_A, goes through try_notarize()
 *   and broadcasts NotarizeVote{cand_B, slot=0} — equivocation.
 *
 * This test demonstrates the gap deterministically:
 *   1. Publish CandidateReceived{cand_A, slot=0} → ConsensusImpl votes
 *   2. crash_losing_last_n(1) — lose the DB write of that vote
 *   3. Restart
 *   4. Publish CandidateReceived{cand_B, slot=0} → ConsensusImpl votes again
 *   5. Two different NotarizeVotes from val 0 on slot 0 → __builtin_trap()
 *
 * Expected: exit code 77 (SIGTRAP) — amnesia equivocation confirmed.
 *
 * Build (regular cmake, FUZZING=ON not required):
 *   cmake --build build-linux --target test_amnesia_poc -- -j$(nproc)
 *   ./build-linux/test/consensus/test_amnesia_poc
 *   echo "exit code: $?"   # expected: 77
 */

#include <cassert>
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

// ── Constants (same as fuzz_pool.cpp) ────────────────────────────────────────

static constexpr size_t N_VALIDATORS = 4;
static constexpr int DRAIN_ROUNDS = 20;
static constexpr int DRAIN_CRASH_ROUNDS = 200;

namespace ton::validator::consensus::simplex {

// ── MockDb (identical to fuzz_pool.cpp) ──────────────────────────────────────

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
    auto it = kv_.find(ks);
    write_log_.push_back({ks, it != kv_.end() ? std::make_optional(it->second.clone()) : std::nullopt});
    kv_[ks] = std::move(value);
    co_return {};
  }

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
    std::optional<td::BufferSlice> prev;
  };

  std::map<std::string, td::BufferSlice> kv_;
  std::vector<WriteEntry> write_log_;
};

// ── MockKeyring (identical to fuzz_pool.cpp) ─────────────────────────────────

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

// ── FuzzBus (identical to fuzz_pool.cpp) ─────────────────────────────────────

class FuzzBus final : public Bus {
 public:
  using Parent = Bus;
  void populate_collator_schedule() override { Bus::populate_collator_schedule(); }
};

// ── Amnesia equivocation tracking ────────────────────────────────────────────
//
// Maps slot → first notarize vote hash from val 0.
// On second vote with a different hash: amnesia equivocation detected → trap.
//
static std::map<td::uint32, td::Bits256> g_our_notar_vote;
static bool g_safety_active = false;  // only trap during the PoC run, not during init drains

// ── AmnesiaObserver ───────────────────────────────────────────────────────────
//
// Differs from fuzz_pool.cpp's FuzzObserver in two ways:
//   1. ValidationRequest → CandidateAccept (allow try_notarize to complete)
//   2. ResolveState → empty ChainStateRef (sufficient for validation stub)
//   3. OutgoingProtocolMessage → track NotarizeVotes from val 0; trap on equivocation

using FuzzBusHandle = td::actor::BusHandle<FuzzBus>;

class AmnesiaObserver final : public td::actor::SpawnsWith<FuzzBus>,
                              public td::actor::ConnectsTo<FuzzBus> {
 public:
  TON_RUNTIME_DEFINE_EVENT_HANDLER();

  explicit AmnesiaObserver(FuzzBus&) {}

  template <>
  void handle(FuzzBusHandle, std::shared_ptr<const StopRequested>) {
    stop();
  }

  // Allow candidates to be notarized: WaitForParent is handled by Pool,
  // but ResolveState and ValidationRequest need stubs that return success.

  template <>
  td::actor::Task<ResolveState::Result> process(FuzzBusHandle, std::shared_ptr<ResolveState>) {
    // Return an empty ChainStateRef — sufficient since our ValidationRequest stub ignores it.
    co_return ResolveState::Result{ChainStateRef{}, std::nullopt};
  }

  template <>
  td::actor::Task<ResolveCandidate::Result> process(FuzzBusHandle, std::shared_ptr<ResolveCandidate>) {
    co_return td::Status::Error("mock");
  }

  template <>
  td::actor::Task<StoreCandidate::ReturnType> process(FuzzBusHandle, std::shared_ptr<StoreCandidate>) {
    co_return td::Unit{};
  }

  // Key difference from fuzz_pool.cpp: return CandidateAccept instead of CandidateReject.
  // This allows try_notarize() to complete and ConsensusImpl to emit NotarizeVote.
  template <>
  td::actor::Task<ValidateCandidateResult> process(FuzzBusHandle, std::shared_ptr<ValidationRequest>) {
    co_return CandidateAccept{0.0};
  }

  // Track NotarizeVotes emitted by val 0 (the local node).
  // All OutgoingProtocolMessage with a NotarizeVote payload originate from val 0
  // (IncomingProtocolMessage from peers is never re-broadcast by Pool).
  // Trap if val 0 emits two different NotarizeVotes for the same slot.
  template <>
  void handle(FuzzBusHandle, std::shared_ptr<const OutgoingProtocolMessage> msg) {
    auto maybe_vote = fetch_tl_object<ton_api::consensus_simplex_vote>(
        msg->message.data.clone(), true);
    if (maybe_vote.is_error()) return;
    auto& v = *maybe_vote.ok();
    if (!v.vote_) return;
    if (v.vote_->get_id() != ton_api::consensus_simplex_notarizeVote::ID) return;
    auto* nv = static_cast<ton_api::consensus_simplex_notarizeVote*>(v.vote_.get());
    if (!nv->id_) return;

    td::uint32 slot = static_cast<td::uint32>(nv->id_->slot_);
    td::Bits256 hash = nv->id_->hash_;

    auto [it, inserted] = g_our_notar_vote.emplace(slot, hash);
    if (!inserted && g_safety_active && it->second != hash) {
      // Val 0 voted notarize for cand_A pre-crash, and for cand_B post-crash
      // on the same slot — amnesia equivocation confirmed.
      fprintf(stderr,
              "[AMNESIA POC] EQUIVOCATION: val 0 voted twice on slot %u\n"
              "  pre-crash:  notarize(cand=%s)\n"
              "  post-crash: notarize(cand=%s)\n",
              slot, it->second.to_hex().c_str(), hash.to_hex().c_str());
      __builtin_trap();
    }
    if (!inserted) it->second = hash;  // update if repeated (same hash, no conflict)
  }

  template <>
  void handle(FuzzBusHandle, std::shared_ptr<const NotarizationObserved>) {}

  template <>
  void handle(FuzzBusHandle, std::shared_ptr<const FinalizationObserved>) {}

  template <>
  void handle(FuzzBusHandle, std::shared_ptr<const LeaderWindowObserved>) {}

  template <>
  void handle(FuzzBusHandle, std::shared_ptr<const TraceEvent>) {}

  template <>
  void handle(FuzzBusHandle, std::shared_ptr<const MisbehaviorReport>) {}
};

}  // namespace ton::validator::consensus::simplex

// ── Harness state ─────────────────────────────────────────────────────────────

using namespace ton;
using namespace ton::validator;
using namespace ton::validator::consensus;
using namespace ton::validator::consensus::simplex;

struct HarnessState {
  std::unique_ptr<td::actor::Scheduler> scheduler;
  std::shared_ptr<td::actor::Runtime> runtime;
  td::actor::BusHandle<FuzzBus> bus;
  td::actor::ActorOwn<MockKeyring> keyring;
  MockDb* db_raw = nullptr;
  ValidatorSessionId session_id;
};

static HarnessState* g_state = nullptr;

static void configure_and_start_bus(HarnessState& S, std::unique_ptr<MockDb> db) {
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
  Consensus::register_in(*S.runtime);
  S.runtime->register_actor<AmnesiaObserver>("AmnesiaObserver");

  S.scheduler->run_in_context([&] {
    S.bus = S.runtime->start(std::move(bus), "amnesia_poc");
  });
  for (int i = 0; i < DRAIN_ROUNDS; i++) S.scheduler->run(0);

  S.scheduler->run_in_context([&] {
    S.bus.publish(std::make_shared<Start>(Start{ChainStateRef{}}));
  });
  for (int i = 0; i < DRAIN_ROUNDS; i++) S.scheduler->run(0);
}

static void crash_and_restart(HarnessState& S, size_t n_lose) {
  S.db_raw->crash_losing_last_n(n_lose);
  auto recovered_db = S.db_raw->clone();

  S.scheduler->run_in_context([&] {
    S.bus.publish(std::make_shared<StopRequested>());
  });
  for (int i = 0; i < DRAIN_CRASH_ROUNDS; i++) S.scheduler->run(0);

  S.bus = {};
  S.runtime.reset();

  configure_and_start_bus(S, std::move(recovered_db));
}

// ── Make a minimal Candidate for slot 0 (no parent → needs BlockCandidate) ──

static CandidateRef make_candidate(td::Bits256 hash) {
  CandidateId id{.slot = 0, .hash = hash};
  // Slot 0 has no parent → must use BlockCandidate variant.
  // BlockCandidate with empty buffers is sufficient: our ValidationRequest
  // stub returns CandidateAccept without parsing the data.
  BlockCandidate bc{};
  bc.id = BlockIdExt{BlockId{basechainId, shardIdAll, 0}};
  return td::make_ref<Candidate>(
      id,
      std::nullopt,           // no parent (first slot)
      PeerValidatorId{1},     // leader = val 1 (any validator, not local)
      std::variant<BlockIdExt, BlockCandidate>(std::in_place_type<BlockCandidate>, std::move(bc)),
      td::BufferSlice(64));   // dummy signature (signature check is bypassed)
}

int main() {
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(ERROR));
  simulation::GraphLogger::instance().init();
  PeerValidator::g_skip_signature_check = true;

  g_state = new HarnessState();
  auto& S = *g_state;

  S.session_id = td::Bits256{};
  S.session_id.as_array()[0] = 0x42;

  // NodeInfo{{0}}: zero CPU threads → deterministic synchronous execution.
  S.scheduler = std::make_unique<td::actor::Scheduler>(
      std::vector<td::actor::Scheduler::NodeInfo>{{0}}, /*skip_timeouts=*/true);

  S.scheduler->run_in_context([&] {
    S.keyring = td::actor::create_actor<MockKeyring>(
        td::actor::ActorOptions{}.with_name("MockKeyring"));
  });

  configure_and_start_bus(S, std::make_unique<MockDb>());

  // ── Step 1: Pre-crash — val 0 votes notarize for cand_A on slot 0 ─────────

  td::Bits256 hash_A{};
  hash_A.as_array()[0] = 0x01;  // cand_A

  auto candidate_A = make_candidate(hash_A);

  S.scheduler->run_in_context([&] {
    S.bus.publish(std::make_shared<CandidateReceived>(CandidateReceived{candidate_A}));
  });
  for (int i = 0; i < DRAIN_ROUNDS; i++) S.scheduler->run(0);

  // Assert: val 0 voted for cand_A (tracked via OutgoingProtocolMessage).
  // If this fails, the try_notarize path didn't complete — check stubs.
  assert(g_our_notar_vote.count(0) > 0 && "val 0 did not vote pre-crash");
  assert(g_our_notar_vote[0] == hash_A && "unexpected pre-crash vote hash");

  // ── Step 2: Crash — lose the DB write of our NotarizeVote ────────────────
  //
  // crash_losing_last_n(1) rolls back the last DB write in MockDb.
  // db.cpp:70-72: `co_await owning_bus()->db->set(key, value)` — this is the
  // write that gets lost. After restart, bootstrap_votes won't include the vote.

  crash_and_restart(S, 1);

  // ── Step 3: Post-crash — val 0 votes notarize for cand_B on slot 0 ───────
  //
  // ConsensusImpl starts fresh after restart. bootstrap_votes has no entry
  // for slot 0 (DB write was lost). voted_notar = nullopt → will vote again.
  // We present a different candidate (cand_B) to trigger equivocation.

  td::Bits256 hash_B{};
  hash_B.as_array()[0] = 0x02;  // cand_B ≠ cand_A

  auto candidate_B = make_candidate(hash_B);

  // Enable the equivocation trap.
  g_safety_active = true;

  S.scheduler->run_in_context([&] {
    S.bus.publish(std::make_shared<CandidateReceived>(CandidateReceived{candidate_B}));
  });
  // The amnesia equivocation trap fires here (inside drain):
  for (int i = 0; i < DRAIN_ROUNDS; i++) S.scheduler->run(0);

  // ── If we reach here, val 0 did not re-vote (gap not triggered) ──────────
  //
  // This would indicate the DB write was NOT lost (n_lose was not enough, or
  // the vote was persisted before crash_losing_last_n ran). Investigate by
  // checking g_our_notar_vote[0] post-restart.
  assert(false && "amnesia: val 0 should have re-voted for cand_B (equivocation expected)");

  return 1;
}
