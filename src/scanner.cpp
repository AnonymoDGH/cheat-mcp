#include "cheatmcp.hpp"

#include <cctype>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <vector>
#include <string>

namespace cmcp {

ScanState& scan_state() {
    static ScanState s;
    return s;
}

// -----------------------------------------------------------------------------
// value <-> bytes
// -----------------------------------------------------------------------------
static size_t type_width(ScanType t) {
    switch (t) {
        case ScanType::I8:  return 1;
        case ScanType::I16: return 2;
        case ScanType::I32: return 4;
        case ScanType::I64: return 8;
        case ScanType::F32: return 4;
        case ScanType::F64: return 8;
        default:            return 0;
    }
}

static std::vector<uint8_t> value_to_bytes(ScanType t, const std::string& text) {
    std::vector<uint8_t> out;
    switch (t) {
        case ScanType::I8:  { int64_t v = std::strtoll(text.c_str(), nullptr, 0); out.push_back((uint8_t)v); break; }
        case ScanType::I16: { int64_t v = std::strtoll(text.c_str(), nullptr, 0); out.resize(2); std::memcpy(out.data(), &v, 2); break; }
        case ScanType::I32: { int64_t v = std::strtoll(text.c_str(), nullptr, 0); out.resize(4); std::memcpy(out.data(), &v, 4); break; }
        case ScanType::I64: { int64_t v = std::strtoll(text.c_str(), nullptr, 0); out.resize(8); std::memcpy(out.data(), &v, 8); break; }
        case ScanType::F32: { float v = (float)std::strtod(text.c_str(), nullptr); out.resize(4); std::memcpy(out.data(), &v, 4); break; }
        case ScanType::F64: { double v = std::strtod(text.c_str(), nullptr); out.resize(8); std::memcpy(out.data(), &v, 8); break; }
        case ScanType::Str: { out.assign(text.begin(), text.end()); out.push_back(0); break; }
        case ScanType::Aob: out = parse_hex(text); break;
    }
    return out;
}

static bool numeric_from_bytes(ScanType t, const uint8_t* p, double& out) {
    switch (t) {
        case ScanType::I8:  { int8_t v;  std::memcpy(&v, p, 1); out = v; return true; }
        case ScanType::I16: { int16_t v; std::memcpy(&v, p, 2); out = v; return true; }
        case ScanType::I32: { int32_t v; std::memcpy(&v, p, 4); out = v; return true; }
        case ScanType::I64: { int64_t v; std::memcpy(&v, p, 8); out = (double)v; return true; }
        case ScanType::F32: { float v;   std::memcpy(&v, p, 4); out = v; return true; }
        case ScanType::F64: { double v;  std::memcpy(&v, p, 8); out = v; return true; }
        default: return false;
    }
}

// -----------------------------------------------------------------------------
// regions
// -----------------------------------------------------------------------------
struct Region { uint64_t base; uint64_t size; };

static std::vector<Region> scannable_regions(uint32_t pid, bool writable_only) {
    std::vector<Region> out;
    for (auto& m : query_regions(pid)) {
        if (m.State != MEM_COMMIT) continue;
        if (m.Protect & PAGE_GUARD) continue;
        if (m.Protect & PAGE_NOACCESS) continue;
        DWORD prot = m.Protect & 0xFF;
        bool readable = (prot == PAGE_READONLY || prot == PAGE_READWRITE ||
                         prot == PAGE_WRITECOPY || prot == PAGE_EXECUTE_READ ||
                         prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY);
        if (!readable) continue;
        bool writable = (prot == PAGE_READWRITE || prot == PAGE_WRITECOPY ||
                         prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY);
        if (writable_only && !writable) continue;
        out.push_back({ (uint64_t)(uintptr_t)m.BaseAddress, (uint64_t)m.RegionSize });
    }
    return out;
}

// -----------------------------------------------------------------------------
// first scan
// -----------------------------------------------------------------------------
size_t scan_first(uint32_t pid, ScanType type, const std::string& value,
                  bool writable_only, size_t max_hits) {
    ScanState& st = scan_state();
    std::lock_guard<std::mutex> lk(st.mtx);

    st.active = true;
    st.type = type;
    st.pattern = value;
    st.hits.clear();

    std::vector<uint8_t> needle = value_to_bytes(type, value);
    size_t w = needle.size();
    st.width = w;
    if (w == 0) return 0;

    const size_t CHUNK = 1 << 20;
    std::vector<uint8_t> buf(CHUNK + w);

    for (auto& r : scannable_regions(pid, writable_only)) {
        uint64_t off = 0;
        while (off < r.size) {
            size_t want = (size_t)std::min<uint64_t>(CHUNK, r.size - off);
            if (!read_mem(pid, r.base + off, buf.data(), want)) { off += want; continue; }
            if (want >= w) {
                for (size_t k = 0; k + w <= want; ++k) {
                    if (std::memcmp(buf.data() + k, needle.data(), w) == 0) {
                        st.hits.push_back({ r.base + off + k, {} });
                        if (st.hits.size() >= max_hits) return st.hits.size();
                    }
                }
            }
            off += want;
        }
    }
    return st.hits.size();
}

// -----------------------------------------------------------------------------
// AOB scan (pattern supports ?? wildcards)
// -----------------------------------------------------------------------------
struct AobByte { uint8_t value; bool wild; };

static std::vector<AobByte> parse_aob(const std::string& pattern) {
    std::vector<AobByte> out;
    size_t k = 0;
    while (k < pattern.size()) {
        char c = pattern[k];
        if (c == '?') {
            out.push_back({ 0, true });
            ++k;
            if (k < pattern.size() && pattern[k] == '?') ++k;
            continue;
        }
        if (std::isxdigit((unsigned char)c)) {
            int v = 0, n = 0;
            while (n < 2 && k < pattern.size() && std::isxdigit((unsigned char)pattern[k])) {
                char h = pattern[k];
                int d = (h >= '0' && h <= '9') ? h - '0'
                      : (h >= 'a' && h <= 'f') ? h - 'a' + 10
                      : h - 'A' + 10;
                v = (v << 4) | d;
                ++k; ++n;
            }
            out.push_back({ (uint8_t)v, false });
            continue;
        }
        ++k;
    }
    return out;
}

size_t scan_aob(uint32_t pid, const std::string& pattern, bool writable_only, size_t max_hits) {
    ScanState& st = scan_state();
    std::lock_guard<std::mutex> lk(st.mtx);

    auto needle = parse_aob(pattern);
    st.active = true;
    st.type = ScanType::Aob;
    st.pattern = pattern;
    st.width = needle.size();
    st.hits.clear();
    if (needle.empty()) return 0;

    const size_t CHUNK = 1 << 20;
    std::vector<uint8_t> buf(CHUNK + needle.size());

    for (auto& r : scannable_regions(pid, writable_only)) {
        uint64_t off = 0;
        while (off < r.size) {
            size_t want = (size_t)std::min<uint64_t>(CHUNK, r.size - off);
            if (!read_mem(pid, r.base + off, buf.data(), want)) { off += want; continue; }
            if (want >= needle.size()) {
                for (size_t k = 0; k + needle.size() <= want; ++k) {
                    bool match = true;
                    for (size_t j = 0; j < needle.size(); ++j) {
                        if (!needle[j].wild && buf[k + j] != needle[j].value) { match = false; break; }
                    }
                    if (match) {
                        st.hits.push_back({ r.base + off + k, {} });
                        if (st.hits.size() >= max_hits) return st.hits.size();
                    }
                }
            }
            off += want;
        }
    }
    return st.hits.size();
}

// -----------------------------------------------------------------------------
// exact-value scan over memory (returns addresses)
// -----------------------------------------------------------------------------
std::vector<uint64_t> scan_exact_value(uint32_t pid, uint64_t value, int width,
                                       bool writable_only, bool aligned, size_t max_hits) {
    std::vector<uint64_t> out;
    if (width != 4 && width != 8) width = 8;
    const size_t w = (size_t)width;

    std::vector<uint8_t> needle(w, 0);
    std::memcpy(needle.data(), &value, w);

    const size_t CHUNK = 1 << 20;
    std::vector<uint8_t> buf(CHUNK + w);
    const size_t step = aligned ? w : 1;

    for (auto& r : scannable_regions(pid, writable_only)) {
        uint64_t off = 0;
        while (off < r.size && out.size() < max_hits) {
            size_t want = (size_t)std::min<uint64_t>(CHUNK, r.size - off);
            if (!read_mem(pid, r.base + off, buf.data(), want)) { off += want; continue; }
            if (want >= w) {
                // align start relative to the region base when requested
                size_t start = 0;
                if (aligned) {
                    uint64_t abs = r.base + off;
                    size_t rem = (size_t)(abs % w);
                    start = rem ? (w - rem) : 0;
                }
                for (size_t k = start; k + w <= want; k += step) {
                    if (std::memcmp(buf.data() + k, needle.data(), w) == 0) {
                        out.push_back(r.base + off + k);
                        if (out.size() >= max_hits) break;
                    }
                }
            }
            off += want;
        }
    }
    return out;
}

// -----------------------------------------------------------------------------
// refine / next scan
// -----------------------------------------------------------------------------
size_t scan_refine(uint32_t pid, const std::string& mode, const std::string& value) {
    ScanState& st = scan_state();
    std::lock_guard<std::mutex> lk(st.mtx);
    if (!st.active) return 0;

    std::string m = lower(mode);
    std::vector<uint8_t> needle = value_to_bytes(st.type, value);
    size_t w = st.width;

    std::vector<uint8_t> cur(w);
    std::vector<ScanHit> keep;
    keep.reserve(st.hits.size() / 2 + 8);

    for (auto& hit : st.hits) {
        if (!read_mem(pid, hit.addr, cur.data(), w)) continue;

        bool pass = false;
        if (m == "exact") {
            pass = !needle.empty() && std::memcmp(cur.data(), needle.data(), w) == 0;
        } else if (m == "changed") {
            pass = hit.prev.empty() ? true : (std::memcmp(cur.data(), hit.prev.data(), w) != 0);
        } else if (m == "unchanged") {
            pass = hit.prev.empty() ? true : (std::memcmp(cur.data(), hit.prev.data(), w) == 0);
        } else if (m == "increased" || m == "decreased") {
            double a = 0, b = 0;
            if (numeric_from_bytes(st.type, cur.data(), a) &&
                numeric_from_bytes(st.type, hit.prev.empty() ? cur.data() : hit.prev.data(), b)) {
                pass = (m == "increased") ? (a > b) : (a < b);
            }
        } else {
            pass = true;
        }

        if (pass) {
            ScanHit nh = hit;
            nh.prev = cur;
            keep.push_back(std::move(nh));
        }
    }

    st.hits.swap(keep);
    return st.hits.size();
}

// -----------------------------------------------------------------------------
// results (with live bytes per hit)
// -----------------------------------------------------------------------------
Json hits_json(uint32_t pid, size_t offset, size_t limit) {
    ScanState& st = scan_state();
    std::lock_guard<std::mutex> lk(st.mtx);

    Json r = Json::obj();
    r.set("total", (long long)st.hits.size());
    r.set("offset", (long long)offset);
    r.set("returned", (long long)std::min(st.hits.size() - std::min(offset, st.hits.size()), limit));

    Json arr = Json::arr();
    size_t end = std::min(st.hits.size(), offset + limit);
    for (size_t k = offset; k < end; ++k) {
        Json h = Json::obj();
        h.set("address", u64_hex(st.hits[k].addr));
        if (pid && st.width && st.width <= 64) {
            std::vector<uint8_t> cur(st.width);
            if (read_mem(pid, st.hits[k].addr, cur.data(), st.width))
                h.set("hex", to_hex(cur.data(), cur.size()));
        }
        arr.push(std::move(h));
    }
    r.set("hits", std::move(arr));
    return r;
}

Json scan_results(size_t offset, size_t limit, uint32_t pid, const std::string& type_name) {
    (void)type_name;
    ScanState& st = scan_state();
    {
        std::lock_guard<std::mutex> lk(st.mtx);
        if (!st.active) {
            Json r = Json::obj();
            r.set("active", false);
            r.set("total", 0);
            r.set("hits", Json::arr());
            return r;
        }
    }
    Json r = hits_json(pid, offset, limit);
    r.set("active", true);
    return r;
}

// -----------------------------------------------------------------------------
// reverse pointer scan (one level)
// -----------------------------------------------------------------------------
Json pointer_scan(uint32_t pid, uint64_t target, size_t max_offset, size_t max_results) {
    Json r = Json::obj();
    Json arr = Json::arr();

    bool is64 = is_process_64(pid);
    const size_t pw = is64 ? 8 : 4;
    const size_t CHUNK = 1 << 20;
    std::vector<uint8_t> buf(CHUNK + pw);

    uint64_t lo = (target > max_offset) ? (target - max_offset) : 0;

    for (auto& reg : scannable_regions(pid, false)) {
        uint64_t off = 0;
        while (off < reg.size && arr.size() < max_results) {
            size_t want = (size_t)std::min<uint64_t>(CHUNK, reg.size - off);
            if (!read_mem(pid, reg.base + off, buf.data(), want)) { off += want; continue; }
            if (want >= pw) {
                for (size_t k = 0; k + pw <= want; k += (is64 ? 4 : 2)) {
                    uint64_t v = 0;
                    std::memcpy(&v, buf.data() + k, pw);
                    if (is64) v &= 0x0000FFFFFFFFFFFFull;
                    if (v >= lo && v <= target) {
                        Json h = Json::obj();
                        h.set("address", u64_hex(reg.base + off + k));
                        h.set("points_to", u64_hex(v));
                        h.set("offset", (long long)(target - v));
                        arr.push(std::move(h));
                        if (arr.size() >= max_results) break;
                    }
                }
            }
            off += want;
        }
    }

    r.set("target", u64_hex(target));
    r.set("pointer_width", (long long)pw);
    r.set("count", (long long)arr.size());
    r.set("results", std::move(arr));
    return r;
}

// -----------------------------------------------------------------------------
// persistence
// -----------------------------------------------------------------------------
bool scan_save(const std::string& path, std::string& err) {
    ScanState& st = scan_state();
    std::lock_guard<std::mutex> lk(st.mtx);

    Json j = Json::obj();
    j.set("version", 1);
    j.set("active", st.active);
    j.set("type", (long long)st.type);
    j.set("width", (long long)st.width);
    j.set("pattern", st.pattern);
    Json arr = Json::arr();
    for (auto& h : st.hits) {
        Json e = Json::obj();
        e.set("a", u64_hex(h.addr));
        if (!h.prev.empty()) e.set("p", to_hex(h.prev.data(), h.prev.size()));
        arr.push(std::move(e));
    }
    j.set("hits", std::move(arr));

    std::ofstream f(path, std::ios::binary);
    if (!f) { err = "cannot open for write: " + path; return false; }
    std::string s = j.dump();
    f.write(s.data(), (std::streamsize)s.size());
    return true;
}

bool scan_load(const std::string& path, std::string& err) {
    std::ifstream f(path, std::ios::binary);
    if (!f) { err = "cannot open: " + path; return false; }
    std::string s((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

    Json j;
    try { j = Json::parse(s); } catch (const std::exception& e) { err = e.what(); return false; }

    ScanState& st = scan_state();
    std::lock_guard<std::mutex> lk(st.mtx);
    st.active = j.has("active") ? j.at("active").as_b() : true;
    st.type = (ScanType)(j.has("type") ? j.at("type").as_i() : (long long)ScanType::I32);
    st.width = (size_t)(j.has("width") ? j.at("width").as_i() : 4);
    st.pattern = j.has("pattern") ? j.at("pattern").as_s() : "";
    st.hits.clear();
    if (j.has("hits")) {
        for (auto& e : j.at("hits").a) {
            ScanHit h;
            h.addr = parse_u64(e.at("a"));
            if (e.has("p")) h.prev = parse_hex(e.at("p").as_s());
            st.hits.push_back(std::move(h));
        }
    }
    return true;
}

void scan_reset() {
    ScanState& st = scan_state();
    std::lock_guard<std::mutex> lk(st.mtx);
    st.active = false;
    st.hits.clear();
    st.pattern.clear();
}

} // namespace cmcp
