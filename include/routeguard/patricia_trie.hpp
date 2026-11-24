#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "routeguard/prefix.hpp"

namespace rg {

// Path-compressed binary trie (Patricia / radix-2 trie). Same interface as
// PrefixTrie, but a chain of single-child nodes collapses into one edge, so
// the trie has at most 2n - 1 nodes for n prefixes instead of up to n * 32
// (IPv4) or n * 128 (IPv6), and a lookup visits at most ~log2(n) nodes
// instead of one node per prefix bit.
//
// Each node stores its full key. A node without a value is a "glue" node
// that exists only where two keys diverge. Nodes live in one vector and are
// linked by index (see PrefixTrie for why).
template <typename V>
class PatriciaTrie {
 public:
  PatriciaTrie() { nodes_.emplace_back(); }  // index 0 = root, the /0 glue node

  V& insert_or_get(const Prefix& p) {
    std::uint32_t node = 0;
    while (true) {
      // Invariant: nodes_[node].key is a prefix of p.
      const int depth = nodes_[node].key.length();
      if (depth == p.length()) return value_at(node, p);

      const int b = p.bit(depth) ? 1 : 0;
      const std::uint32_t child = nodes_[node].child[b];
      if (child == kNone) {
        const auto leaf = new_node(p);
        nodes_[node].child[b] = leaf;
        return value_at(leaf, p);
      }

      const Prefix child_key = nodes_[child].key;
      const int common = Prefix::common_length(child_key, p, std::min(child_key.length(), p.length()));
      if (common == child_key.length()) {  // child is still on p's path
        node = child;
        continue;
      }

      // p diverges from child's key inside the edge node -> child: split it.
      if (common == p.length()) {  // p sits on the edge: becomes child's parent
        const auto mid = new_node(p);
        nodes_[mid].child[child_key.bit(common) ? 1 : 0] = child;
        nodes_[node].child[b] = mid;
        return value_at(mid, p);
      }
      const auto glue = new_node(p.truncated(common));
      const auto leaf = new_node(p);
      nodes_[glue].child[child_key.bit(common) ? 1 : 0] = child;
      nodes_[glue].child[p.bit(common) ? 1 : 0] = leaf;
      nodes_[node].child[b] = glue;
      return value_at(leaf, p);
    }
  }

  const V* find_exact(const Prefix& p) const {
    std::uint32_t node = 0;
    while (true) {
      const Node& n = nodes_[node];
      const int depth = n.key.length();
      if (depth > p.length() || Prefix::common_length(n.key, p, depth) < depth) return nullptr;
      if (depth == p.length()) return n.value ? &*n.value : nullptr;
      node = n.child[p.bit(depth) ? 1 : 0];
      if (node == kNone) return nullptr;
    }
  }

  // Calls visit(prefix, value) for every stored prefix covering `p`, from
  // least to most specific.
  //
  // Only nodes holding a value are compared against p in full. Glue nodes
  // are passed through on their branch bit alone: every key below a glue
  // node extends the glue key, so if the skipped bits differ, the next
  // valued node fails its comparison and the walk stops there.
  template <typename F>
  void for_each_covering(const Prefix& p, F&& visit) const {
    std::uint32_t node = 0;
    while (true) {
      const Node& n = nodes_[node];
      const int depth = n.key.length();
      if (depth > p.length()) return;
      if (n.value) {
        if (Prefix::common_length(n.key, p, depth) < depth) return;
        visit(n.key, *n.value);
      }
      if (depth == p.length()) return;
      node = n.child[p.bit(depth) ? 1 : 0];
      if (node == kNone) return;
    }
  }

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
  std::size_t memory_bytes() const noexcept { return nodes_.capacity() * sizeof(Node); }

 private:
  static constexpr std::uint32_t kNone = 0;  // the root is never a child

  struct Node {
    Prefix key;
    std::uint32_t child[2]{kNone, kNone};
    std::optional<V> value;
  };

  std::uint32_t new_node(const Prefix& key) {
    const auto idx = static_cast<std::uint32_t>(nodes_.size());
    nodes_.emplace_back();  // may reallocate: callers use indices, not references
    nodes_[idx].key = key;
    return idx;
  }

  V& value_at(std::uint32_t node, const Prefix& key) {
    Node& n = nodes_[node];
    if (!n.value) {
      n.value.emplace();
      n.key = key;  // the root's key starts as a placeholder /0 of either family
      ++size_;
    }
    return *n.value;
  }

  std::vector<Node> nodes_;
  std::size_t size_ = 0;
};

}  // namespace rg
