#include "test_framework.hpp"

int main() {
  for (const auto& test : rgtest::registry()) {
    const int before = rgtest::failures();
    test.fn();
    std::cout << (rgtest::failures() == before ? "[ OK ] " : "[FAIL] ") << test.name << '\n';
  }
  std::cout << rgtest::registry().size() << " tests, " << rgtest::failures() << " failed checks\n";
  return rgtest::failures() == 0 ? 0 : 1;
}
