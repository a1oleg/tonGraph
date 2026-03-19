/*
 * Copyright (c) 2025-2026, TON CORE TECHNOLOGIES CO. L.L.C
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 *
 * Phase 2, Step 2 fuzzer: pool.cpp via BusRuntime + MockDb.
 *
 * Exercises the vote-accumulation logic of PoolImpl with the real actor
 * runtime.  Ed25519 signature verification is bypassed via
 * PeerValidator::g_skip_signature_check so libFuzzer can mutate vote
 * content freely while still exercising accumulation, cert-creation and
 * WAL (MockDb) paths.
 *
 * Fuzz input layout (FuzzedDataProvider):
 *   n_messages : uint8  (0..15)
 *   per message:
 *     src_idx   : uint8  (0..N_VALIDATORS-1)
 *     vote_type : uint8  (0=notarize, 1=skip, 2=finalize)
 *     slot      : uint8  (0..MAX_SLOT)
 *     cand_seed : uint8  (0..N_CAND_SEEDS-1)
 *
 * Build (FUZZING=ON cmake build, e.g. the "build" directory):
 *   cmake --build build --target fuzz_pool -- -j$(nproc)
 *
 * Test run (1 hour):
 *   REPO=$(pwd)
 *   mkdir -p simulation/corpus_fuzz_pool simulation/crashes_pool
 *   tmux new-session -d -s fuzz_pool \
 *     "cd $REPO && timeout 3600 ./build/test/consensus/fuzz_pool \
 *      $REPO/simulation/corpus_fuzz_pool/ \
 *      -max_total_time=3600 -jobs=$(nproc) \
 *      -artifact_prefix=$REPO/simulation/crashes_pool/ \
 *      >> $REPO/simulation/fuzz_pool.log 2>&1"
 */

#include <fuzzer/FuzzedDataProvider.h>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "auto/tl/ton_api.h"
#include "auto/tl/ton_api.hpp"
#include "consensus/simplex/bus.h"
#include "consensus/bus.h"
#include "consensus/types.h"
#include "keys/keys.hpp"
#include "td/actor/BusRuntime.h"
#include "td/actor/actor.h"
#include "td/actor/common.h"
#include "tl-utils/common-utils.hpp"
#include "ton/ton-types.h"

#include "simulation/GraphLogger.h"
#include "td/utils/logging.h"

// ─────────────────────────────────────────────────────────────────────────────

static constexpr size_t N_VALIDATORS = 4;
static constexpr uint8_t MAX_SLOT = 15;
static constexpr uint8_t N_CAND_SEEDS = 4;
static constexpr int DRAIN_ROUNDS = 20;

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
    kv_[key.as_slice().str()] = std::move(value);
    co_return {};
  }

 private:
  std::map<std::string, td::BufferSlice> kv_;
};

// ── FuzzBus ───────────────────────────────────────────────────────────────────

class FuzzBus final : public Bus {
 public:
  void populate_collator_schedule() override {
    Bus::populate_collator_schedule();
  }
};

// Invariant-tracking globals (written by FuzzObserver, checked inline)
static std::map<td::uint32, td::Bits256> g_notar_by_slot;
static std::map<td::uint32, td::Bits256> g_skip_by_slot;

// ── FuzzObserver ──────────────────────────────────────────────────────────────

using FuzzBusHandle = td::actor::BusHandle<FuzzBus>;

class FuzzObserver final : public td::actor::SpawnsWith<FuzzBus>,
                           public td::actor::ConnectsTo<FuzzBus> {
 public:
  TON_RUNTIME_DEFINE_EVENT_HANDLER();

  explicit FuzzObserver(FuzzBus&) {}

  // Use FuzzBusHandle explicitly to match the template instantiation
  template <>
  void handle(FuzzBusHandle, std::shared_ptr<const StopRequested>) {
    stop();
  }

  template <>
  void handle(FuzzBusHandle, std::shared_ptr<const NotarizationObserved> ev) {
    td::uint32 slot = ev->certificate->vote.id.slot;
    auto hash = ev->certificate->vote.id.hash;

    // SAFETY: NotarCert + SkipCert on same slot
    if (g_skip_by_slot.count(slot)) {
      __builtin_trap();  // dual cert: notarize+skip on same slot
    }
    // SAFETY: two different NotarCerts on same slot
    auto [it, inserted] = g_notar_by_slot.emplace(slot, hash);
    if (!inserted && it->second != hash) {
      __builtin_trap();  // dual cert: two different notarizations
    }
  }

  template <>
  void handle(FuzzBusHandle, std::shared_ptr<const FinalizationObserved>) {
    // Could add finalization invariant checks here
  }

  template <>
  void handle(FuzzBusHandle, std::shared_ptr<const OutgoingProtocolMessage>) {}

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
  ValidatorSessionId session_id;
  td::Bits256 cand_hashes[N_CAND_SEEDS];
};

static FuzzState* g_state = nullptr;

// ── One-time initialization ───────────────────────────────────────────────────

extern "C" int LLVMFuzzerInitialize(int*, char***) {
  // Suppress BusRuntime and pool.cpp verbose logging
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(ERROR));

  // Disable GraphLogger
  simulation::GraphLogger::instance().init();

  // Bypass Ed25519 signature verification
  PeerValidator::g_skip_signature_check = true;

  g_state = new FuzzState();
  auto& S = *g_state;

  // Fixed session id and candidate hashes
  S.session_id = td::Bits256{};
  S.session_id.as_array()[0] = 0x42;
  for (size_t i = 0; i < N_CAND_SEEDS; i++) {
    S.cand_hashes[i] = td::Bits256{};
    S.cand_hashes[i].as_array()[0] = static_cast<uint8_t>(i + 1);
  }

  // Configure bus
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
  bus->db = std::make_unique<MockDb>();

  // Build runtime and register actors
  S.runtime = std::make_shared<td::actor::Runtime>();
  Pool::register_in(*S.runtime);
  simplex::Db::register_in(*S.runtime);
  S.runtime->register_actor<FuzzObserver>("FuzzObserver");

  // Single-threaded scheduler, skip_timeouts=true for deterministic drain
  S.scheduler = std::make_unique<td::actor::Scheduler>(
      std::vector<td::actor::Scheduler::NodeInfo>{{1}}, /*skip_timeouts=*/true);

  S.scheduler->run_in_context([&] {
    S.bus = S.runtime->start(std::move(bus), "fuzz_pool");
  });

  // Drain initialization (DbImpl reads MockDb, Pool::start_up runs)
  for (int i = 0; i < DRAIN_ROUNDS; i++) {
    S.scheduler->run(0);
  }

  return 0;
}

// ── Per-iteration fuzzing ─────────────────────────────────────────────────────

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 1) return 0;

  FuzzedDataProvider fdp(data, size);
  uint8_t n_messages = fdp.ConsumeIntegralInRange<uint8_t>(0, 15);

  for (uint8_t m = 0; m < n_messages && fdp.remaining_bytes() >= 4; m++) {
    auto src_idx   = fdp.ConsumeIntegralInRange<uint8_t>(0, N_VALIDATORS - 1);
    auto vote_type = fdp.ConsumeIntegralInRange<uint8_t>(0, 2);
    auto slot      = fdp.ConsumeIntegralInRange<uint8_t>(0, MAX_SLOT);
    auto cand_seed = fdp.ConsumeIntegralInRange<uint8_t>(0, N_CAND_SEEDS - 1);

    auto& S = *g_state;

    // Build vote TL
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

    // Signed vote TL with dummy 64-byte signature (check is bypassed)
    auto signed_vote_tl = create_tl_object<ton_api::consensus_simplex_vote>(
        std::move(vote_tl), td::BufferSlice(64));

    auto msg_bytes = serialize_tl_object(signed_vote_tl, true);
    auto msg = std::make_shared<IncomingProtocolMessage>(
        PeerValidatorId{src_idx}, ProtocolMessage{std::move(msg_bytes)});

    S.scheduler->run_in_context([&] {
      S.bus.publish(msg);
    });

    // Drain event queue (~3 coroutine round-trips needed for cert path)
    for (int i = 0; i < DRAIN_ROUNDS; i++) {
      S.scheduler->run(0);
    }
  }

  return 0;
}
