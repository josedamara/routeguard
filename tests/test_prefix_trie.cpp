#include <random>
#include <string>
#include <vector>

#include "routeguard/patricia_trie.hpp"
#include "routeguard/prefix_trie.hpp"
#include "test_framework.hpp"

using rg::Prefix;

namespace {

Prefix P(const char* s) { return *Prefix::parse(s); }

template <template <typename> class Trie>
void check_longest_prefix_match() {
  Trie<std::string> trie;
  trie.insert_or_get(P("0.0.0.0/0")) = "default";
  trie.insert_or_get(P("10.0.0.0/8")) = "ten";
  trie.insert_or_get(P("10.1.0.0/16")) = "ten-one";

  Prefix matched;
  const auto* v = trie.longest_match(P("10.1.2.0/24"), &matched);
  RG_CHECK(v != nullptr && *v == "ten-one");
  RG_CHECK(matched == P("10.1.0.0/16"));
  v = trie.longest_match(P("10.2.0.0/16"));
  RG_CHECK(v != nullptr && *v == "ten");
  v = trie.longest_match(P("192.0.2.0/24"));
  RG_CHECK(v != nullptr && *v == "default");
  RG_CHECK(trie.size() == 3);
}

template <template <typename> class Trie>
void check_exact_and_missing() {
  Trie<int> trie;
  trie.insert_or_get(P("10.0.0.0/8")) = 1;
  RG_CHECK(trie.find_exact(P("10.0.0.0/8")) != nullptr);
  RG_CHECK(trie.find_exact(P("10.0.0.0/9")) == nullptr);
  RG_CHECK(trie.find_exact(P("0.0.0.0/0")) == nullptr);
  RG_CHECK(trie.longest_match(P("11.0.0.0/8")) == nullptr);  // no default route

  trie.insert_or_get(P("10.0.0.0/8")) += 1;  // same key: no new entry
  RG_CHECK(trie.size() == 1);
  RG_CHECK(*trie.find_exact(P("10.0.0.0/8")) == 2);
}

template <template <typename> class Trie>
void check_covering_order() {
  Trie<int> trie;
  trie.insert_or_get(P("2001:db8::/32")) = 32;
  trie.insert_or_get(P("2001:db8::/48")) = 48;
  trie.insert_or_get(P("2001:db8:1::/48")) = 99;  // sibling, must not be visited

  std::vector<int> seen;
  trie.for_each_covering(P("2001:db8::/64"), [&](const Prefix&, int v) { seen.push_back(v); });
  RG_CHECK((seen == std::vector<int>{32, 48}));
}

// Random prefixes clustered in a small address space so they nest and
// diverge a lot; every query is checked against a brute-force scan.
template <template <typename> class Trie>
void check_against_brute_force(rg::Family family) {
  std::mt19937 rng(family == rg::Family::V4 ? 7 : 11);
  const int max_len = family == rg::Family::V4 ? 32 : 128;
  auto random_prefix = [&](int max_bits) {
    std::uint8_t bytes[16] = {};
    bytes[0] = static_cast<std::uint8_t>(0x20 | (rng() & 0x3));  // shared high bits
    for (int i = 1; i < 16; ++i) bytes[i] = static_cast<std::uint8_t>(rng() & (i < 3 ? 0xFF : 0x0F));
    const int len = static_cast<int>(rng() % static_cast<unsigned>(max_bits + 1));
    return *Prefix::from_bytes(family, bytes, 16, len);
  };

  Trie<int> trie;
  std::vector<std::pair<Prefix, int>> reference;
  for (int i = 0; i < 2000; ++i) {
    const Prefix p = random_prefix(std::min(max_len, 28));
    int& slot = trie.insert_or_get(p);
    slot = i;
    bool replaced = false;
    for (auto& [q, v] : reference) {
      if (q == p) {
        v = i;
        replaced = true;
      }
    }
    if (!replaced) reference.emplace_back(p, i);
  }
  RG_CHECK(trie.size() == reference.size());

  int mismatches = 0;
  for (int i = 0; i < 3000; ++i) {
    const Prefix query = random_prefix(max_len);
    std::vector<int> expected;  // covering values, least specific first
    for (int len = 0; len <= query.length(); ++len) {
      for (const auto& [q, v] : reference) {
        if (q.length() == len && q.covers(query)) expected.push_back(v);
      }
    }
    std::vector<int> got;
    trie.for_each_covering(query, [&](const Prefix&, int v) { got.push_back(v); });
    const int* lpm = trie.longest_match(query);
    if (got != expected) ++mismatches;
    if ((lpm == nullptr) != expected.empty() || (lpm != nullptr && *lpm != expected.back())) ++mismatches;
  }
  RG_CHECK(mismatches == 0);
}

}  // namespace

RG_TEST(trie_longest_prefix_match) { check_longest_prefix_match<rg::PrefixTrie>(); }
RG_TEST(trie_exact_and_missing) { check_exact_and_missing<rg::PrefixTrie>(); }
RG_TEST(trie_for_each_covering_order) { check_covering_order<rg::PrefixTrie>(); }
RG_TEST(trie_matches_brute_force) {
  check_against_brute_force<rg::PrefixTrie>(rg::Family::V4);
  check_against_brute_force<rg::PrefixTrie>(rg::Family::V6);
}

RG_TEST(patricia_longest_prefix_match) { check_longest_prefix_match<rg::PatriciaTrie>(); }
RG_TEST(patricia_exact_and_missing) { check_exact_and_missing<rg::PatriciaTrie>(); }
RG_TEST(patricia_for_each_covering_order) { check_covering_order<rg::PatriciaTrie>(); }
RG_TEST(patricia_matches_brute_force) {
  check_against_brute_force<rg::PatriciaTrie>(rg::Family::V4);
  check_against_brute_force<rg::PatriciaTrie>(rg::Family::V6);
}

RG_TEST(patricia_is_compact) {
  rg::PatriciaTrie<int> patricia;
  rg::PrefixTrie<int> binary;
  for (int i = 0; i < 256; ++i) {
    const std::uint8_t bytes[4] = {10, static_cast<std::uint8_t>(i), 0, 0};
    const auto p = *Prefix::from_bytes(rg::Family::V4, bytes, 4, 24);
    patricia.insert_or_get(p) = i;
    binary.insert_or_get(p) = i;
  }
  RG_CHECK(patricia.node_count() <= 2 * patricia.size());  // n leaves + < n glue + root
  RG_CHECK(binary.node_count() > 3 * patricia.node_count());
}
