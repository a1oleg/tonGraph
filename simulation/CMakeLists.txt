cmake_minimum_required(VERSION 3.16)

find_package(Threads REQUIRED)

# ── ConsensusHarness — Byzantine scenario simulator ─────────────────────────

add_executable(ConsensusHarness
    ConsensusHarness.cpp
    GraphLogger.cpp
)

target_compile_features(ConsensusHarness PRIVATE cxx_std_17)

target_include_directories(ConsensusHarness PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# No external dependencies — pure C++17 stdlib only.
target_link_libraries(ConsensusHarness PRIVATE Threads::Threads)

set_target_properties(ConsensusHarness PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/simulation"
)

# ── fuzz_harness — libFuzzer protocol-level fuzzer ──────────────────────────
# Requires clang and FUZZING=ON. Example:
#
#   cmake -B build-fuzz \
#     -DCMAKE_C_COMPILER=clang-18 -DCMAKE_CXX_COMPILER=clang++-18 \
#     -DFUZZING=ON -G Ninja
#   cmake --build build-fuzz --target fuzz_harness
#
# Standalone replay (no fuzzer, with GraphLogger):
#   cmake -B build-fuzz -DFUZZING=OFF ...
#   cmake --build build-fuzz --target fuzz_harness_standalone

if(FUZZING)
  # libFuzzer mode: -fsanitize=fuzzer links the fuzzer engine and defines
  # FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION (suppresses main())
  add_executable(fuzz_harness
      fuzz_harness.cpp
      GraphLogger.cpp
  )
  target_compile_features(fuzz_harness PRIVATE cxx_std_17)
  target_include_directories(fuzz_harness PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  target_compile_options(fuzz_harness PRIVATE
      -fsanitize=fuzzer
      -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
      -g -O1
  )
  target_link_options(fuzz_harness PRIVATE -fsanitize=fuzzer)
  target_link_libraries(fuzz_harness PRIVATE Threads::Threads)
  set_target_properties(fuzz_harness PROPERTIES
      RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/simulation"
  )
endif()

# Standalone replay binary (always built alongside ConsensusHarness)
add_executable(fuzz_harness_standalone
    fuzz_harness.cpp
    GraphLogger.cpp
)
target_compile_features(fuzz_harness_standalone PRIVATE cxx_std_17)
target_include_directories(fuzz_harness_standalone PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(fuzz_harness_standalone PRIVATE -g)
target_link_libraries(fuzz_harness_standalone PRIVATE Threads::Threads)
set_target_properties(fuzz_harness_standalone PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/simulation"
)
