cmake_minimum_required(VERSION 3.20)
project(routeguard VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

option(ROUTEGUARD_SANITIZE "Build with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)
option(ROUTEGUARD_WERROR "Treat warnings as errors" OFF)
option(ROUTEGUARD_BUILD_TESTS "Build unit tests" ON)
option(ROUTEGUARD_BUILD_BENCH "Build benchmarks" ON)
option(ROUTEGUARD_FUZZ "Build libFuzzer targets (clang only)" OFF)

# Shared warning / sanitizer flags, applied to every target we own.
add_library(routeguard_flags INTERFACE)
target_compile_options(routeguard_flags INTERFACE -Wall -Wextra -Wpedantic -Wshadow)
if(ROUTEGUARD_WERROR)
  target_compile_options(routeguard_flags INTERFACE -Werror)
endif()
if(ROUTEGUARD_SANITIZE)
  target_compile_options(routeguard_flags INTERFACE -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_link_options(routeguard_flags INTERFACE -fsanitize=address,undefined)
endif()

# Core library: everything except main().
add_library(routeguard_core
  src/prefix.cpp
  src/rpki.cpp
  src/bgp_update.cpp
  src/aspa.cpp
  src/state_store.cpp
  src/mrt.cpp
)
target_include_directories(routeguard_core PUBLIC include PRIVATE src)
target_link_libraries(routeguard_core PUBLIC routeguard_flags)

# CLI: validate a stream of BGP updates against a ROA/VRP table.
add_executable(routeguard apps/routeguard.cpp)
target_link_libraries(routeguard PRIVATE routeguard_core)

# Agents: separate processes sharing state through the shared-memory store.
foreach(agent ingest validator alert)
  add_executable(routeguard-${agent} apps/agents/${agent}.cpp)
  target_link_libraries(routeguard-${agent} PRIVATE routeguard_core)
endforeach()

if(ROUTEGUARD_BUILD_BENCH)
  foreach(bench bench_lookup bench_store)
    add_executable(${bench} bench/${bench}.cpp)
    target_link_libraries(${bench} PRIVATE routeguard_core)
  endforeach()
endif()

if(ROUTEGUARD_FUZZ)
  # Compiled from source (not linked against routeguard_core) so the decoder
  # itself gets libFuzzer's coverage instrumentation.
  add_executable(fuzz_mrt fuzz/fuzz_mrt.cpp src/mrt.cpp src/prefix.cpp src/bgp_update.cpp)
  target_include_directories(fuzz_mrt PRIVATE include src)
  target_compile_options(fuzz_mrt PRIVATE -g -O1 -fsanitize=fuzzer,address,undefined)
  target_link_options(fuzz_mrt PRIVATE -fsanitize=fuzzer,address,undefined)
endif()

if(ROUTEGUARD_BUILD_TESTS)
  enable_testing()
  add_executable(routeguard_tests
    tests/test_main.cpp
    tests/test_prefix.cpp
    tests/test_prefix_trie.cpp
    tests/test_rpki.cpp
    tests/test_bgp_update.cpp
    tests/test_aspa.cpp
    tests/test_state_store.cpp
    tests/test_mrt.cpp
  )
  target_link_libraries(routeguard_tests PRIVATE routeguard_core)
  target_include_directories(routeguard_tests PRIVATE src)
  add_test(NAME unit COMMAND routeguard_tests)
  add_test(NAME cli_sample
    COMMAND routeguard --roas ${CMAKE_SOURCE_DIR}/data/sample_roas.csv
                       --updates ${CMAKE_SOURCE_DIR}/data/sample_updates.txt)
  add_test(NAME pipeline
    COMMAND bash ${CMAKE_SOURCE_DIR}/tests/pipeline_test.sh $<TARGET_FILE_DIR:routeguard> ${CMAKE_SOURCE_DIR}/data)
endif()
