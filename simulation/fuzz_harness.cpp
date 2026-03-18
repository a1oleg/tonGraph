// fuzz_harness.cpp — libFuzzer harness for simplex consensus protocol simulation.
//
// Fuzzes the *protocol-level* state machine (ConsensusHarness logic), not the
// C++ implementation internals. Goal: find combinations of Byzantine inputs that
// violate safety/liveness invariants of the simplex consensus protocol.
//
// Build:
//   FUZZING=1 cmake -B build-fuzz \
//     -DCMAKE_C_COMPILER=clang-18 -DCMAKE_CXX_COMPILER=clang++-18 -G Ninja
//   cmake --build build-fuzz --target fuzz_harness
//
// Run:
//   ./build-fuzz/simulation/fuzz_harness simulation/corpus_fuzz/ \
//     -max_total_time=3600 -jobs=$(nproc) -artifact_prefix=simulation/crashes/
//
// Crashes are saved to simulation/crashes/ with the minimized input.
// For each crash, set GRAPH_LOGGING_ENABLED=1 and replay via fuzz_harness <input>
// to get a trace, then run relay.mjs to push anomaly to Neo4j.

#include "GraphLogger.h"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

using namespace simulation;

// ── Fuzz input reader ───────────────────────────────────────────────────────
// Reads bytes from the fuzz input one at a time. When exhausted, wraps around
// (so even small inputs exercise the full simulation).

struct FuzzReader {
  const uint8_t* data;
  size_t size;
  size_t pos{0};

  // Read one byte in [0, modulo)
  uint8_t next(uint8_t modulo) {
    if (modulo <= 1) return 0;
    if (size == 0) return 0;
    uint8_t v = data[pos % size];
    pos++;
    return v % modulo;
  }

  bool next_bool() { return next(2) == 1; }
};

// ── Config (derived from fuzz input) ───────────────────────────────────────

static constexpr int MIN_VALIDATORS = 3;
static constexpr int MAX_VALIDATORS = 6;
static constexpr int MAX_SLOTS      = 15;
static constexpr int MAX_BYZ        = 1;  // f=1 Byzantine tolerance

// Per-slot, per-validator action chosen by fuzzer
enum class ValidatorAction : uint8_t {
  Honest         = 0,  // deliver and vote honestly
  DropReceive    = 1,  // pretend candidate never arrived (→ SkipVote)
  DoubleNotarize = 2,  // send NotarizeVote for two different candidateIds
  NotarizeAndSkip = 3, // send both NotarizeVote AND SkipVote (known undetected bug)
  NoVote         = 4,  // simply abstain (liveness test)
  COUNT          = 5,
};

// ── Invariant tracking ──────────────────────────────────────────────────────

struct InvariantError {
  std::string description;
  uint32_t slot;
};

struct SessionInvariants {
  // slot → set of certified candidateIds (certType = finalize)
  std::map<uint32_t, std::set<std::string>> finalize_certs;
  // slot → set of (validatorIdx, voteType) pairs
  std::map<uint32_t, std::map<int, std::set<std::string>>> votes_by_slot;

  std::vector<InvariantError> errors;

  void record_vote(uint32_t slot, int validator, const std::string& type,
                   const std::string& candidateId = "") {
    votes_by_slot[slot][validator].insert(type + ":" + candidateId);
  }

  void record_finalize_cert(uint32_t slot, const std::string& candidateId) {
    finalize_certs[slot].insert(candidateId);
  }

  void check(uint32_t slot) {
    // [Safety] Two different FinalizeCerts on same slot = state divergence
    if (finalize_certs.count(slot) && finalize_certs[slot].size() > 1) {
      errors.push_back({"SAFETY VIOLATION: dual FinalizeCert on slot", slot});
    }

    // [Safety] Validator has both NotarizeVote and SkipVote in same slot
    if (votes_by_slot.count(slot)) {
      for (auto& [vidx, vtypes] : votes_by_slot[slot]) {
        bool has_notarize = false, has_skip = false;
        for (auto& vt : vtypes) {
          if (vt.rfind("notarize:", 0) == 0) has_notarize = true;
          if (vt.rfind("skip:", 0)     == 0) has_skip     = true;
        }
        if (has_notarize && has_skip) {
          errors.push_back({"INVARIANT VIOLATION: notarize+skip from validator "
                            + std::to_string(vidx) + " on slot", slot});
        }
      }
    }
  }
};

// ── Slot runner ─────────────────────────────────────────────────────────────

static std::string session_id_global;

static std::string candidate_hex(uint32_t slot, int variant = 0) {
  std::ostringstream ss;
  ss << std::hex << std::setfill('0')
     << std::setw(8) << (slot * 1000 + variant)
     << std::string(56, '0');  // 64-char hex
  return ss.str();
}

static void run_fuzz_slot(FuzzReader& rdr, int N, uint32_t slot,
                          SessionInvariants& inv, int& finalized, int& skipped) {
  auto& log = GraphLogger::instance();
  const int leader = (int)(slot % (uint32_t)N);
  const int threshold = N - MAX_BYZ;  // f=1

  auto emit = [&](const std::string& ev, Props props) {
    props["sessionId"] = session_id_global;
    props["slot"]      = (int64_t)slot;
    log.emit(ev, props);
  };

  // Leader proposes a candidate
  std::string cand_main = candidate_hex(slot, 0);
  emit("Propose", {{"leaderIdx", (int64_t)leader}, {"candidateId", cand_main}});

  // Per-validator action chosen by fuzzer
  std::vector<ValidatorAction> actions(N);
  for (int v = 0; v < N; v++) {
    actions[v] = static_cast<ValidatorAction>(rdr.next((uint8_t)ValidatorAction::COUNT));
  }

  // Decide delivery: did each validator receive the candidate?
  std::vector<bool> received(N, true);
  for (int v = 0; v < N; v++) {
    if (actions[v] == ValidatorAction::DropReceive) received[v] = false;
  }

  for (int v = 0; v < N; v++) {
    if (received[v] && v != leader) {
      emit("CandidateReceived", {
          {"receiverIdx",  (int64_t)v},
          {"leaderIdx",    (int64_t)leader},
          {"candidateId",  cand_main},
          {"parentSlot",   (int64_t)(slot > 0 ? slot - 1 : 0)},
      });
    }
  }

  // Collect notarize votes
  std::map<std::string, int> notarize_weight;  // candidateId → weight
  std::vector<bool> did_notarize(N, false);
  std::vector<bool> did_skip(N, false);

  for (int v = 0; v < N; v++) {
    if (!received[v]) continue;

    switch (actions[v]) {
      case ValidatorAction::Honest: {
        emit("VoteCast", {{"validatorIdx", (int64_t)v},
                          {"candidateId",  cand_main},
                          {"voteType",     std::string("notarize")}});
        inv.record_vote(slot, v, "notarize", cand_main);
        notarize_weight[cand_main]++;
        did_notarize[v] = true;
        break;
      }
      case ValidatorAction::DoubleNotarize: {
        // Equivocation: vote for two different candidates
        std::string cand_b = candidate_hex(slot, 1);
        emit("VoteCast", {{"validatorIdx", (int64_t)v},
                          {"candidateId",  cand_main},
                          {"voteType",     std::string("notarize")}});
        emit("VoteCast", {{"validatorIdx", (int64_t)v},
                          {"candidateId",  cand_b},
                          {"voteType",     std::string("notarize")}});
        inv.record_vote(slot, v, "notarize", cand_main);
        inv.record_vote(slot, v, "notarize", cand_b);
        notarize_weight[cand_main]++;
        notarize_weight[cand_b]++;
        did_notarize[v] = true;
        break;
      }
      case ValidatorAction::NotarizeAndSkip: {
        // Known protocol gap: notarize + skip in same slot (pool.cpp doesn't detect this)
        emit("VoteCast", {{"validatorIdx", (int64_t)v},
                          {"candidateId",  cand_main},
                          {"voteType",     std::string("notarize")}});
        emit("VoteCast", {{"validatorIdx", (int64_t)v},
                          {"candidateId",  std::string("")},
                          {"voteType",     std::string("skip")}});
        inv.record_vote(slot, v, "notarize", cand_main);
        inv.record_vote(slot, v, "skip", "");
        notarize_weight[cand_main]++;
        did_notarize[v] = true;
        did_skip[v]     = true;
        break;
      }
      case ValidatorAction::NoVote:
      case ValidatorAction::DropReceive:
      case ValidatorAction::COUNT:
        break;
    }
  }

  // Find the candidateId with the most notarize votes
  std::string winning_cand;
  int max_weight = 0;
  for (auto& [cid, w] : notarize_weight) {
    if (w > max_weight) { max_weight = w; winning_cand = cid; }
  }

  if (max_weight >= threshold) {
    // NotarizeCert formed
    emit("CertIssued", {{"certType",    std::string("notarize")},
                        {"candidateId", winning_cand},
                        {"weight",      (int64_t)max_weight}});

    // FinalizeVotes from validators who notarized this candidate
    int finalize_w = 0;
    for (int v = 0; v < N; v++) {
      if (did_notarize[v] && !did_skip[v]) {
        emit("VoteCast", {{"validatorIdx", (int64_t)v},
                          {"candidateId",  winning_cand},
                          {"voteType",     std::string("finalize")}});
        finalize_w++;
      }
    }

    if (finalize_w >= threshold) {
      emit("CertIssued", {{"certType",    std::string("finalize")},
                          {"candidateId", winning_cand},
                          {"weight",      (int64_t)finalize_w}});
      emit("BlockAccepted", {{"candidateId", winning_cand}});
      inv.record_finalize_cert(slot, winning_cand);
      finalized++;
    }
  } else {
    // No quorum → SkipVotes from non-notarizing validators
    int skip_w = 0;
    for (int v = 0; v < N; v++) {
      if (!did_notarize[v]) {
        emit("VoteCast", {{"validatorIdx", (int64_t)v},
                          {"candidateId",  std::string("")},
                          {"voteType",     std::string("skip")}});
        inv.record_vote(slot, v, "skip", "");
        skip_w++;
      }
    }
    if (skip_w >= threshold) {
      emit("CertIssued", {{"certType",    std::string("skip")},
                          {"candidateId", std::string("")},
                          {"weight",      (int64_t)skip_w}});
      skipped++;
    }
  }

  inv.check(slot);
}

// ── libFuzzer entry point ───────────────────────────────────────────────────

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 3) return 0;  // need at least: n_validators, n_slots, 1 action byte

  FuzzReader rdr{data, size};

  const int n_validators = MIN_VALIDATORS + rdr.next((uint8_t)(MAX_VALIDATORS - MIN_VALIDATORS + 1));
  const int n_slots      = 1 + rdr.next((uint8_t)MAX_SLOTS);

  // Generate a deterministic session id from input hash
  {
    std::ostringstream ss;
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0; i < size; i++) h = (h ^ data[i]) * 1099511628211ULL;
    ss << std::hex << std::setfill('0') << std::setw(16) << h
       << std::setw(16) << (h * 6364136223846793005ULL + 1442695040888963407ULL);
    session_id_global = ss.str() + std::string(32, '0');
    session_id_global.resize(64);
  }

  GraphLogger::instance().emit("SessionStart", {
      {"sessionId",  session_id_global},
      {"scenario",   std::string("fuzz")},
      {"validators", (int64_t)n_validators},
      {"slots",      (int64_t)n_slots},
  });

  SessionInvariants inv;
  int finalized = 0, skipped = 0;

  for (int s = 0; s < n_slots; s++) {
    run_fuzz_slot(rdr, n_validators, (uint32_t)s, inv, finalized, skipped);
  }

  GraphLogger::instance().emit("SessionEnd", {
      {"sessionId",      session_id_global},
      {"finalizedBlocks",(int64_t)finalized},
      {"skippedSlots",   (int64_t)skipped},
  });

  // ── Invariant assertions → libFuzzer treats abort() as a crash ─────────
  for (auto& err : inv.errors) {
    // Safety violations abort immediately (crash saved by libFuzzer)
    if (err.description.rfind("SAFETY VIOLATION", 0) == 0) {
      fprintf(stderr, "[fuzz] %s (slot=%u) sessionId=%s\n",
              err.description.c_str(), err.slot, session_id_global.c_str());
      __builtin_trap();  // crash → libFuzzer saves the input
    }

    // Protocol invariant violations: log but don't abort (known bugs tracked via Neo4j)
    if (err.description.rfind("INVARIANT VIOLATION", 0) == 0) {
      fprintf(stderr, "[fuzz] %s (slot=%u)\n",
              err.description.c_str(), err.slot);
    }
  }

  return 0;
}

// ── Standalone mode (replay a crash file or run with GraphLogger) ───────────
// Usage: ./fuzz_harness [input_file]
// If no file: run built-in seed corpus for smoke test.

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION

#include <fstream>

static void run_from_bytes(const std::vector<uint8_t>& bytes) {
  LLVMFuzzerTestOneInput(bytes.data(), bytes.size());
}

int main(int argc, char* argv[]) {
  GraphLogger::instance().init();

  if (argc >= 2) {
    // Replay a crash file
    std::ifstream f(argv[1], std::ios::binary);
    if (!f) { fprintf(stderr, "Cannot open %s\n", argv[1]); return 1; }
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(f)),
                                std::istreambuf_iterator<char>());
    fprintf(stderr, "[fuzz] replaying %zu bytes from %s\n", bytes.size(), argv[1]);
    run_from_bytes(bytes);
    return 0;
  }

  // Seed corpus: run predefined scenarios to verify harness works
  fprintf(stderr, "[fuzz] smoke test with seed corpus\n");

  // honest: N=4, 5 slots, all validators honest
  run_from_bytes({4, 5,
    0,0,0,0,  // slot 0: all honest
    0,0,0,0,  // slot 1
    0,0,0,0,  // slot 2
    0,0,0,0,  // slot 3
    0,0,0,0   // slot 4
  });

  // equivocation: validator 0 double-votes
  run_from_bytes({4, 3,
    2,0,0,0,  // slot 0: v0 DoubleNotarize
    2,0,0,0,  // slot 1
    2,0,0,0   // slot 2
  });

  // notarize_skip_split: validator 0 notarizes AND skips
  run_from_bytes({4, 3,
    3,0,0,0,  // slot 0: v0 NotarizeAndSkip
    3,0,0,0,
    3,0,0,0
  });

  // message withholding: leader drops proposal
  run_from_bytes({4, 2,
    1,4,4,4,  // slot 0: leader drops; others no-vote
    0,0,0,0
  });

  fprintf(stderr, "[fuzz] smoke test done\n");
  return 0;
}

#endif  // FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
