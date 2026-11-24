#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <utility>
#include <vector>

#include "routeguard/prefix.hpp"

namespace rg {

// Binary trie keyed by prefix bits, one level per bit. Use one trie per
// address family (the trie itself does not look at Prefix::family()).
//
// Nodes live in one contiguous vector and refer to each other by index rather
// than by pointer: fewer allocations, better cache behaviour, and the whole
// structure could later be placed in shared memory (stage 2) because indices
// stay valid across processes while pointers do not.
//
// TODO(stage 5): path-compress this into a Patricia trie and benchmark
// lookups/sec and memory against this baseline on a full routing table.
template <typename V>
class PrefixTrie {
 public:
  PrefixTrie() { nodes_.emplace_back(); }  // index 0 = root (the /0 node)

  // Returns the value stored at exactly `p`, default-constructing it if absent.
  V& insert_or_get(const Prefix& p) {
    std::uint32_t node = 0;
    for (int depth = 0; depth < p.length(); ++depth) {
      const int b = p.bit(depth) ? 1 : 0;
      if (nodes_[node].child[b] == kNone) {
        const auto idx = static_cast<std::uint32_t>(nodes_.size());
        nodes_.emplace_back();  // may reallocate: never hold Node& across this
        nodes_[node].child[b] = idx;
      }
      node = nodes_[node].child[b];
    }
    auto& entry = nodes_[node].entry;
    if (!entry) {
      entry.emplace(p, V{});
      ++size_;
    }
    return entry->second;
  }

  const V* find_exact(const Prefix& p) const {
    std::uint32_t node = 0;
    for (int depth = 0; depth < p.length(); ++depth) {
      node = nodes_[node].child[p.bit(depth) ? 1 : 0];
      if (node == kNone) return nullptr;
    }
    const auto& entry = nodes_[node].entry;
    return entry ? &entry->second : nullptr;
  }

  // Calls visit(prefix, value) for every stored prefix that covers `p`
  // (including `p` itself), from least to most specific. O(p.length()).
  template <typename F>
  void for_each_covering(const Prefix& p, F&& visit) const {
    std::uint32_t node = 0;
    for (int depth = 0;; ++depth) {
      if (const auto& entry = nodes_[node].entry) visit(entry->first, entry->second);
      if (depth == p.length()) return;
      node = nodes_[node].child[p.bit(depth) ? 1 : 0];
      if (node == kNone) return;
    }
  }

  // Longest-prefix match: the most specific stored prefix covering `p`.
  const V* longest_match(const Prefix& p, Prefix* matched = nullptr) const {
    const V* best = nullptr;
    for_each_covering(p, [&](const Prefix& q, const V& v) {
      best = &v;
      if (matched != nullptr) *matched = q;
    });
    return best;
  }

  std::size_t size() const noexcept { return size_; }
  std::size_t node_count() const noexcept { return nodes_.size(); }

 private:
  // The root is index 0 and is never anyone's child, so 0 can mean "no child".
  static constexpr std::uint32_t kNone = 0;

  struct Node {
    std::uint32_t child[2]{kNone, kNone};
    std::optional<std::pair<Prefix, V>> entry;
  };

  std::vector<Node> nodes_;
  std::size_t size_ = 0;
};

}  // namespace rg
