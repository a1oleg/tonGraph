/*
 * Copyright (c) 2025-2026, TON CORE TECHNOLOGIES CO. L.L.C
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 *
 * Phase 2 fuzzer: TL deserialization of simplex consensus wire types.
 *
 * Targets the TL parsing layer that pool.cpp uses before any crypto/actor
 * runtime is involved. Catches: buffer overflows, out-of-bounds reads,
 * assertion failures, and integer overflow in the TL parser.
 *
 * Build:
 *   cmake -B build-fuzz-pool \
 *     -DCMAKE_C_COMPILER=clang-18 -DCMAKE_CXX_COMPILER=clang++-18 \
 *     -DFUZZING=ON -G Ninja
 *   cmake --build build-fuzz-pool --target fuzz_tl
 *
 * Run:
 *   REPO=$(pwd)
 *   ./build-fuzz-pool/test/consensus/fuzz_tl \
 *     "$REPO/simulation/corpus_fuzz_tl/" \
 *     -max_total_time=86400 -jobs=$(nproc) \
 *     -artifact_prefix="$REPO/simulation/crashes_tl/"
 */

#include "auto/tl/ton_api.h"
#include "tl-utils/common-utils.hpp"

using namespace ton;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  td::Slice slice(reinterpret_cast<const char*>(data), size);

  // ── Vote types ─────────────────────────────────────────────────────────────

  // consensus.simplex.vote vote:UnsignedVote signature:bytes = Vote
  fetch_tl_object<ton_api::consensus_simplex_vote>(slice, true).ignore();

  // consensus.simplex.certificate vote:UnsignedVote signatures:VoteSignatureSet
  fetch_tl_object<ton_api::consensus_simplex_certificate>(slice, true).ignore();

  // consensus.simplex.voteSignatureSet votes:(vector VoteSignature)
  fetch_tl_object<ton_api::consensus_simplex_voteSignatureSet>(slice, true).ignore();

  // consensus.simplex.voteSignature who:int signature:bytes
  fetch_tl_object<ton_api::consensus_simplex_voteSignature>(slice, true).ignore();

  // consensus.simplex.candidateAndCert candidate:bytes notar:bytes
  fetch_tl_object<ton_api::consensus_simplex_candidateAndCert>(slice, true).ignore();

  // ── DB types ───────────────────────────────────────────────────────────────

  // consensus.simplex.db.ourVote vote:UnsignedVote seqno:long
  fetch_tl_object<ton_api::consensus_simplex_db_ourVote>(slice, true).ignore();

  // consensus.simplex.db.cert cert:Certificate
  fetch_tl_object<ton_api::consensus_simplex_db_cert>(slice, true).ignore();

  // consensus.simplex.db.poolState first_nonannounced_window:int
  fetch_tl_object<ton_api::consensus_simplex_db_poolState>(slice, true).ignore();

  // consensus.simplex.db.finalizedBlock block_id parent is_final
  fetch_tl_object<ton_api::consensus_simplex_db_finalizedBlock>(slice, true).ignore();

  return 0;
}
