#pragma once

// Test helper that encodes BGP4MP MRT records byte by byte, so the decoder
// is tested against the wire format rather than against itself.

#include <cstdint>
#include <initializer_list>
#include <vector>

namespace rgtest {

class Bytes {
 public:
  Bytes& u8(std::uint32_t v) {
    b_.push_back(static_cast<std::uint8_t>(v));
    return *this;
  }
  Bytes& u16(std::uint32_t v) { return u8(v >> 8).u8(v); }
  Bytes& u32(std::uint32_t v) { return u16(v >> 16).u16(v); }
  Bytes& raw(const std::vector<std::uint8_t>& v) {
    b_.insert(b_.end(), v.begin(), v.end());
    return *this;
  }
  Bytes& raw(std::initializer_list<std::uint8_t> v) {
    b_.insert(b_.end(), v.begin(), v.end());
    return *this;
  }
  const std::vector<std::uint8_t>& data() const { return b_; }
  std::size_t size() const { return b_.size(); }

 private:
  std::vector<std::uint8_t> b_;
};

// One NLRI entry: <bits><significant bytes>.
inline std::vector<std::uint8_t> nlri(std::initializer_list<std::uint8_t> addr, int bits) {
  std::vector<std::uint8_t> out{static_cast<std::uint8_t>(bits)};
  auto it = addr.begin();
  for (int i = 0; i < (bits + 7) / 8; ++i) out.push_back(*it++);
  return out;
}

struct Segment {
  std::uint8_t type;  // 1 = AS_SET, 2 = AS_SEQUENCE
  std::vector<std::uint32_t> asns;
};

inline std::vector<std::uint8_t> attr(std::uint8_t type, const std::vector<std::uint8_t>& value) {
  Bytes b;
  b.u8(0x50).u8(type).u16(static_cast<std::uint32_t>(value.size())).raw(value);  // extended length
  return b.data();
}

inline std::vector<std::uint8_t> as_path_attr(std::vector<Segment> segs, int asn_size = 4, std::uint8_t type = 2) {
  Bytes v;
  for (const auto& s : segs) {
    v.u8(s.type).u8(static_cast<std::uint32_t>(s.asns.size()));
    for (auto asn : s.asns) asn_size == 4 ? v.u32(asn) : v.u16(asn);
  }
  return attr(type, v.data());
}

inline std::vector<std::uint8_t> mp_reach_v6(const std::vector<std::uint8_t>& nlri_bytes) {
  Bytes v;
  v.u16(2).u8(1).u8(16);
  for (int i = 0; i < 16; ++i) v.u8(i == 0 ? 0x20 : 0);  // next hop 2000::
  v.u8(0).raw(nlri_bytes);
  return attr(14, v.data());
}

inline std::vector<std::uint8_t> mp_unreach_v6(const std::vector<std::uint8_t>& nlri_bytes) {
  Bytes v;
  v.u16(2).u8(1).raw(nlri_bytes);
  return attr(15, v.data());
}

struct UpdateSpec {
  std::uint32_t timestamp = 1763337600;
  bool as4 = true;
  std::uint32_t peer_as = 64510;
  std::uint8_t bgp_type = 2;  // UPDATE
  std::vector<std::uint8_t> withdrawn;
  std::vector<std::uint8_t> attrs;
  std::vector<std::uint8_t> nlri;
};

// Full MRT record: 12-byte MRT header + BGP4MP header + BGP message.
inline std::vector<std::uint8_t> mrt_record(const UpdateSpec& s) {
  Bytes msg;
  msg.u16(static_cast<std::uint32_t>(s.withdrawn.size())).raw(s.withdrawn);
  msg.u16(static_cast<std::uint32_t>(s.attrs.size())).raw(s.attrs).raw(s.nlri);

  Bytes body;
  if (s.as4) {
    body.u32(s.peer_as).u32(64999);
  } else {
    body.u16(s.peer_as).u16(64999);
  }
  body.u16(0).u16(1);              // ifindex, AFI IPv4
  body.raw({192, 0, 2, 254});      // peer IP
  body.raw({192, 0, 2, 1});        // local IP
  for (int i = 0; i < 16; ++i) body.u8(0xFF);
  body.u16(static_cast<std::uint32_t>(19 + msg.size())).u8(s.bgp_type).raw(msg.data());

  Bytes rec;
  rec.u32(s.timestamp).u16(16).u16(s.as4 ? 4 : 1).u32(static_cast<std::uint32_t>(body.size())).raw(body.data());
  return rec.data();
}

}  // namespace rgtest
