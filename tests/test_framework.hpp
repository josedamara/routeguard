#pragma once

// A deliberately tiny test harness so the project builds with no downloads.
// Swap it for GoogleTest (FetchContent) or Catch2 once the project grows.

#include <iostream>
#include <vector>

namespace rgtest {

struct Case {
  const char* name;
  void (*fn)();
};

inline std::vector<Case>& registry() {
  static std::vector<Case> cases;
  return cases;
}

inline int& failures() {
  static int count = 0;
  return count;
}

struct Registrar {
  Registrar(const char* name, void (*fn)()) { registry().push_back({name, fn}); }
};

}  // namespace rgtest

#define RG_TEST(name)                                                 \
  static void name();                                                 \
  static const ::rgtest::Registrar name##_registrar{#name, &name};    \
  static void name()

#define RG_CHECK(cond)                                                                  \
  do {                                                                                  \
    if (!(cond)) {                                                                      \
      ++::rgtest::failures();                                                           \
      std::cerr << __FILE__ << ':' << __LINE__ << ": CHECK failed: " #cond << '\n';     \
    }                                                                                   \
  } while (0)
