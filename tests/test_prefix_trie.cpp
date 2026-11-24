#include <string>
#include <vector>

#include "routeguard/prefix_trie.hpp"
#include "test_framework.hpp"

using rg::Prefix;

namespace {
Prefix P(const char* s) { return *Prefix::parse(s); }
}  // namespace

RG_TEST(trie_longest_prefix_match) {
  rg::PrefixTrie<std::string> trie;
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

RG_TEST(trie_exact_and_missing) {
  rg::PrefixTrie<int> trie;
  trie.insert_or_get(P("10.0.0.0/8")) = 1;
  RG_CHECK(trie.find_exact(P("10.0.0.0/8")) != nullptr);
  RG_CHECK(trie.find_exact(P("10.0.0.0/9")) == nullptr);
  RG_CHECK(trie.longest_match(P("11.0.0.0/8")) == nullptr);  // no default route

  trie.insert_or_get(P("10.0.0.0/8")) += 1;  // same key: no new entry
  RG_CHECK(trie.size() == 1);
  RG_CHECK(*trie.find_exact(P("10.0.0.0/8")) == 2);
}

RG_TEST(trie_for_each_covering_order) {
  rg::PrefixTrie<int> trie;
  trie.insert_or_get(P("2001:db8::/32")) = 32;
  trie.insert_or_get(P("2001:db8::/48")) = 48;
  trie.insert_or_get(P("2001:db8:1::/48")) = 99;  // sibling, must not be visited

  std::vector<int> seen;
  trie.for_each_covering(P("2001:db8::/64"), [&](const Prefix&, int v) { seen.push_back(v); });
  RG_CHECK((seen == std::vector<int>{32, 48}));
}
