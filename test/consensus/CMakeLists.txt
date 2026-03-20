add_executable(test-consensus test-consensus.cpp)
target_link_libraries(test-consensus overlay tdutils tdactor adnl adnltest rldp tl_api dht validator ton_validator validator)
# add_test(test-consensus test-consensus)

# ── test_amnesia_poc — Amnesia equivocation standalone PoC ───────────────────
# No FUZZING=ON required. Demonstrates that ConsensusImpl broadcasts
# NotarizeVote before DbImpl persists it, enabling equivocation after restart.
# Expected exit code: 77 (SIGTRAP via __builtin_trap).
add_executable(test_amnesia_poc test_amnesia_poc.cpp)
target_compile_options(test_amnesia_poc PRIVATE -g -O1)
target_link_libraries(test_amnesia_poc PRIVATE
    tl_api tdutils tdactor tl-utils
    validator ton_validator
    keys adnl overlay keyring
)
target_include_directories(test_amnesia_poc PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/simulation
)

# ── fuzz_tl — Phase 2 TL deserialization fuzzer ──────────────────────────────
# Requires clang and FUZZING=ON in the top-level build:
#
#   cmake -B build-fuzz-pool \
#     -DCMAKE_C_COMPILER=clang-18 -DCMAKE_CXX_COMPILER=clang++-18 \
#     -DFUZZING=ON -G Ninja
#   cmake --build build-fuzz-pool --target fuzz_tl
#
if(FUZZING)
  add_executable(fuzz_tl fuzz_tl.cpp)
  target_compile_options(fuzz_tl PRIVATE
      -fsanitize=fuzzer
      -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
      -g -O1
  )
  target_link_options(fuzz_tl PRIVATE -fsanitize=fuzzer)
  target_link_libraries(fuzz_tl PRIVATE tl_api tdutils tl-utils)

  # ── fuzz_pool — Phase 2 Step 2+3: pool.cpp via BusRuntime + MockDb + crash ───
  add_executable(fuzz_pool fuzz_pool.cpp)
  target_compile_options(fuzz_pool PRIVATE
      -fsanitize=fuzzer
      -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
      -g -O1
  )
  target_link_options(fuzz_pool PRIVATE -fsanitize=fuzzer)
  target_link_libraries(fuzz_pool PRIVATE
      tl_api tdutils tdactor tl-utils
      validator ton_validator
      keys adnl overlay keyring
  )
  target_include_directories(fuzz_pool PRIVATE
      ${CMAKE_SOURCE_DIR}
      ${CMAKE_SOURCE_DIR}/simulation
  )
endif()
