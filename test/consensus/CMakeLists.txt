add_executable(test-consensus test-consensus.cpp)
target_link_libraries(test-consensus overlay tdutils tdactor adnl adnltest rldp tl_api dht validator ton_validator validator)
# add_test(test-consensus test-consensus)

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
endif()
