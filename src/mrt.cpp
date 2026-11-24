#include "routeguard/mrt.hpp"

#include <arpa/inet.h>
#include <sys/socket.h>

#include <string>

namespace rg {
namespace {

constexpr std::uint16_t kTypeBgp4mp = 16;
constexpr std::uint16_t kTypeBgp4mpEt = 17;
constexpr std::uint16_t kSubMessage = 1;
constexpr std::uint16_t kSubMessageAs4 = 4;
constexpr std::uint16_t kSubMessageLocal = 6;
constexpr std::uint16_t kSubMessageAs4Local = 7;

constexpr std::uint8_t kBgpUpdate = 2;
constexpr std::uint8_t kAttrAsPath = 2;
constexpr std::uint8_t kAttrMpReach = 14;
constexpr std::uint8_t kAttrMpUnreach = 15;
constexpr std::uint8_t kAttrAs4Path = 17;
constexpr std::uint8_t kAttrFlagExtendedLength = 0x10;

constexpr std::uint8_t kSegAsSet = 1;
constexpr std::uint8_t kSegAsSequence = 2;
constexpr std::uint8_t kSegConfedSet = 4;  // 3 = AS_CONFED_SEQUENCE, 4 = AS_CONFED_SET

constexpr std::size_t kMaxRecordLength = 16U << 20;

// Big-endian reader that never goes out of bounds. After the first failed
// read every accessor returns 0 / empty and ok() stays false, so decoding
// code can read a whole structure and check ok() once.
class Cursor {
 public:
  explicit Cursor(std::span<const std::uint8_t> data) : d_(data) {}

  bool ok() const noexcept { return ok_; }
  std::size_t remaining() const noexcept { return ok_ ? d_.size() - pos_ : 0; }

  std::uint8_t u8() { return need(1) ? d_[pos_++] : 0; }
  std::uint16_t u16() {
    if (!need(2)) return 0;
    const auto v = static_cast<std::uint16_t>((d_[pos_] << 8) | d_[pos_ + 1]);
    pos_ += 2;
    return v;
  }
  std::uint32_t u32() {
    if (!need(4)) return 0;
    const std::uint32_t v = (std::uint32_t{d_[pos_]} << 24) | (std::uint32_t{d_[pos_ + 1]} << 16) |
                            (std::uint32_t{d_[pos_ + 2]} << 8) | std::uint32_t{d_[pos_ + 3]};
    pos_ += 4;
    return v;
  }
  std::span<const std::uint8_t> take(std::size_t n) {
    if (!need(n)) return {};
    const auto s = d_.subspan(pos_, n);
    pos_ += n;
    return s;
  }
  std::span<const std::uint8_t> rest() { return take(remaining()); }

 private:
  bool need(std::size_t n) {
    if (!ok_ || d_.size() - pos_ < n) ok_ = false;
    return ok_;
  }

  std::span<const std::uint8_t> d_;
  std::size_t pos_ = 0;
  bool ok_ = true;
};

std::optional<Family> family_for_afi(std::uint16_t afi) {
  if (afi == 1) return Family::V4;
  if (afi == 2) return Family::V6;
  return std::nullopt;
}

// NLRI encoding (RFC 4271 4.3): <length in bits><ceil(length/8) bytes>...
bool read_nlri(std::span<const std::uint8_t> data, Family family, std::vector<Prefix>& out) {
  Cursor c(data);
  while (c.remaining() > 0) {
    const int bits = c.u8();
    const auto bytes = c.take(static_cast<std::size_t>((bits + 7) / 8));
    if (!c.ok()) return false;
    const auto prefix = Prefix::from_bytes(family, bytes.data(), bytes.size(), bits);
    if (!prefix) return false;
    out.push_back(*prefix);
  }
  return c.ok();
}

struct AsPath {
  std::vector<std::uint32_t> hops;  // AS_SEQUENCE members only
  std::size_t length = 0;           // RFC 4271 path length: a set counts as 1
  bool ends_in_set = false;
};

bool read_as_path(std::span<const std::uint8_t> data, std::size_t asn_size, AsPath& path) {
  Cursor c(data);
  while (c.remaining() > 0) {
    const std::uint8_t type = c.u8();
    const std::uint8_t count = c.u8();
    if (type < kSegAsSet || type > kSegConfedSet) return false;
    for (int i = 0; i < count; ++i) {
      const std::uint32_t asn = asn_size == 4 ? c.u32() : c.u16();
      if (type == kSegAsSequence) path.hops.push_back(asn);
    }
    if (!c.ok()) return false;
    if (type == kSegAsSequence) {
      path.length += count;
      path.ends_in_set = false;
    } else if (type == kSegAsSet) {
      path.length += 1;
      path.ends_in_set = true;
    }
    // Confederation segments (types 3 and 4) are local to the confederation
    // and ignored, as for path length.
  }
  return true;
}

// RFC 6793 section 4.2.3: on a 2-byte session the real path is the leading
// part of AS_PATH followed by AS4_PATH.
AsPath merge_as4_path(AsPath as_path, AsPath as4_path) {
  if (as4_path.length > as_path.length) return as_path;  // ignore a bogus AS4_PATH
  const std::size_t keep = as_path.hops.size() >= as4_path.hops.size()
                               ? as_path.hops.size() - as4_path.hops.size()
                               : 0;
  AsPath merged;
  merged.hops.assign(as_path.hops.begin(), as_path.hops.begin() + static_cast<std::ptrdiff_t>(keep));
  merged.hops.insert(merged.hops.end(), as4_path.hops.begin(), as4_path.hops.end());
  merged.length = as_path.length;
  merged.ends_in_set = as4_path.ends_in_set;
  return merged;
}

std::string format_ip(std::span<const std::uint8_t> ip) {
  char buf[INET6_ADDRSTRLEN] = {};
  inet_ntop(ip.size() == 16 ? AF_INET6 : AF_INET, ip.data(), buf, sizeof buf);
  return buf;
}

}  // namespace

MrtResult decode_mrt_record(std::uint32_t timestamp, std::uint16_t type, std::uint16_t subtype,
                            std::span<const std::uint8_t> body, std::vector<BgpUpdate>& out) {
  if (type != kTypeBgp4mp && type != kTypeBgp4mpEt) return MrtResult::Skipped;
  bool as4 = false;
  switch (subtype) {
    case kSubMessage:
    case kSubMessageLocal: as4 = false; break;
    case kSubMessageAs4:
    case kSubMessageAs4Local: as4 = true; break;
    default: return MrtResult::Skipped;  // state changes, ADD-PATH variants
  }

  Cursor c(body);
  if (type == kTypeBgp4mpEt) c.take(4);  // microsecond timestamp
  const std::uint32_t peer_as = as4 ? c.u32() : c.u16();
  if (as4) {
    c.u32();  // local AS
  } else {
    c.u16();
  }
  c.u16();  // interface index
  const auto afi_family = family_for_afi(c.u16());
  if (!c.ok() || !afi_family) return MrtResult::Malformed;
  const std::size_t ip_len = *afi_family == Family::V4 ? 4 : 16;
  const auto peer_ip = c.take(ip_len);
  c.take(ip_len);  // local IP

  // BGP message header: 16-byte marker, length, type.
  c.take(16);
  const std::uint16_t msg_len = c.u16();
  const std::uint8_t msg_type = c.u8();
  if (!c.ok() || msg_len < 19) return MrtResult::Malformed;
  if (msg_type != kBgpUpdate) return MrtResult::Skipped;
  Cursor u(c.take(msg_len - 19U));
  if (!c.ok()) return MrtResult::Malformed;

  const auto withdrawn_data = u.take(u.u16());
  const auto attr_data = u.take(u.u16());
  const auto nlri_data = u.rest();
  if (!u.ok()) return MrtResult::Malformed;

  std::vector<Prefix> withdrawn, announced;
  if (!read_nlri(withdrawn_data, Family::V4, withdrawn)) return MrtResult::Malformed;
  if (!read_nlri(nlri_data, Family::V4, announced)) return MrtResult::Malformed;

  AsPath as_path, as4_path;
  bool have_as4_path = false;
  Cursor a(attr_data);
  while (a.remaining() > 0) {
    const std::uint8_t flags = a.u8();
    const std::uint8_t attr_type = a.u8();
    const std::size_t len = (flags & kAttrFlagExtendedLength) != 0 ? a.u16() : a.u8();
    const auto value = a.take(len);
    if (!a.ok()) return MrtResult::Malformed;

    switch (attr_type) {
      case kAttrAsPath:
        if (!read_as_path(value, as4 ? 4 : 2, as_path)) return MrtResult::Malformed;
        break;
      case kAttrAs4Path:
        if (!read_as_path(value, 4, as4_path)) return MrtResult::Malformed;
        have_as4_path = true;
        break;
      case kAttrMpReach:
      case kAttrMpUnreach: {
        Cursor m(value);
        const auto fam = family_for_afi(m.u16());
        const std::uint8_t safi = m.u8();
        if (attr_type == kAttrMpReach) {
          m.take(m.u8());  // next hop
          m.u8();          // reserved
        }
        const auto nlri = m.rest();
        if (!m.ok()) return MrtResult::Malformed;
        if (!fam || safi != 1) break;  // only unicast IPv4/IPv6
        auto& dest = attr_type == kAttrMpReach ? announced : withdrawn;
        if (!read_nlri(nlri, *fam, dest)) return MrtResult::Malformed;
        break;
      }
      default: break;
    }
  }
  if (!as4 && have_as4_path) as_path = merge_as4_path(std::move(as_path), std::move(as4_path));

  const std::string peer = format_ip(peer_ip);
  for (const auto& prefix : withdrawn) {
    BgpUpdate w;
    w.timestamp = timestamp;
    w.kind = UpdateKind::Withdraw;
    w.peer_ip = peer;
    w.peer_asn = peer_as;
    w.prefix = prefix;
    out.push_back(std::move(w));
  }
  for (const auto& prefix : announced) {
    BgpUpdate ann;
    ann.timestamp = timestamp;
    ann.kind = UpdateKind::Announce;
    ann.peer_ip = peer;
    ann.peer_asn = peer_as;
    ann.prefix = prefix;
    ann.as_path = as_path.hops;
    ann.origin_is_set = as_path.ends_in_set;
    out.push_back(std::move(ann));
  }
  return MrtResult::Decoded;
}

namespace {

void account(MrtStats& stats, MrtResult r, std::size_t produced, std::size_t bytes) {
  ++stats.records;
  stats.bytes += bytes;
  switch (r) {
    case MrtResult::Decoded:
      ++stats.updates;
      stats.prefixes += produced;
      break;
    case MrtResult::Skipped: ++stats.skipped; break;
    case MrtResult::Malformed: ++stats.malformed; break;
  }
}

}  // namespace

std::size_t decode_mrt_buffer(std::span<const std::uint8_t> data, std::vector<BgpUpdate>& out,
                              MrtStats* stats) {
  std::size_t pos = 0;
  while (data.size() - pos >= 12) {
    Cursor h(data.subspan(pos, 12));
    const std::uint32_t timestamp = h.u32();
    const std::uint16_t type = h.u16();
    const std::uint16_t subtype = h.u16();
    const std::uint32_t length = h.u32();
    if (length > data.size() - pos - 12) break;
    const std::size_t before = out.size();
    const auto r = decode_mrt_record(timestamp, type, subtype, data.subspan(pos + 12, length), out);
    if (stats != nullptr) account(*stats, r, out.size() - before, 12 + std::size_t{length});
    pos += 12 + std::size_t{length};
  }
  return pos;
}

bool MrtReader::next(std::vector<BgpUpdate>& out) {
  std::uint8_t header[12];
  in_.read(reinterpret_cast<char*>(header), sizeof header);
  if (in_.gcount() == 0) return false;
  if (in_.gcount() != sizeof header) {
    ++stats_.malformed;
    return false;
  }
  Cursor h(header);
  const std::uint32_t timestamp = h.u32();
  const std::uint16_t type = h.u16();
  const std::uint16_t subtype = h.u16();
  const std::uint32_t length = h.u32();
  if (length > kMaxRecordLength) {
    ++stats_.malformed;
    return false;
  }
  body_.resize(length);
  in_.read(reinterpret_cast<char*>(body_.data()), static_cast<std::streamsize>(length));
  if (static_cast<std::uint32_t>(in_.gcount()) != length) {
    ++stats_.malformed;
    return false;
  }
  const std::size_t before = out.size();
  const auto r = decode_mrt_record(timestamp, type, subtype, body_, out);
  account(stats_, r, out.size() - before, sizeof header + length);
  return true;
}

}  // namespace rg
