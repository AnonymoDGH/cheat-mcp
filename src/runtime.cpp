#include "cheatmcp.hpp"

#include <cstring>
#include <cstdio>
#include <vector>
#include <deque>
#include <map>
#include <atomic>
#include <chrono>

namespace cmcp {

// =============================================================================
// freeze manager
// =============================================================================
struct FreezeEntry {
    int id;
    uint32_t pid;
    uint64_t addr;
    std::vector<uint8_t> data;
    bool active = true;
};

static std::mutex g_freeze_mtx;
static std::vector<FreezeEntry> g_freezes;
static std::atomic<int> g_next_id{1};

Json freeze_add(uint32_t pid, uint64_t addr, const std::vector<uint8_t>& data) {
    std::lock_guard<std::mutex> lk(g_freeze_mtx);
    FreezeEntry e;
    e.id = g_next_id++;
    e.pid = pid;
    e.addr = addr;
    e.data = data;
    g_freezes.push_back(e);
    Json r = Json::obj();
    r.set("id", (long long)e.id);
    r.set("pid", (long long)pid);
    r.set("address", u64_hex(addr));
    r.set("bytes", to_hex(data.data(), data.size()));
    return r;
}

Json freeze_remove(int id) {
    std::lock_guard<std::mutex> lk(g_freeze_mtx);
    Json r = Json::obj();
    for (size_t k = 0; k < g_freezes.size(); ++k) {
        if (g_freezes[k].id == id) { g_freezes.erase(g_freezes.begin() + k); r.set("removed", true); return r; }
    }
    r.set("removed", false);
    return r;
}

Json freeze_list() {
    std::lock_guard<std::mutex> lk(g_freeze_mtx);
    Json arr = Json::arr();
    for (auto& e : g_freezes) {
        Json j = Json::obj();
        j.set("id", (long long)e.id);
        j.set("pid", (long long)e.pid);
        j.set("address", u64_hex(e.addr));
        j.set("bytes", to_hex(e.data.data(), e.data.size()));
        arr.push(std::move(j));
    }
    Json r = Json::obj();
    r.set("count", (long long)arr.size());
    r.set("freezes", std::move(arr));
    return r;
}

// =============================================================================
// watch manager
// =============================================================================
struct WatchSample {
    uint64_t t_ms;
    std::string hex;
};

struct WatchEntry {
    int id;
    uint32_t pid;
    uint64_t addr;
    size_t width;
    std::string type;
    std::vector<uint8_t> last;
    std::deque<WatchSample> history;   // bounded series
};

static const size_t kMaxWatchHistory = 1024;

static std::mutex g_watch_mtx;
static std::vector<WatchEntry> g_watches;
static std::atomic<int> g_watch_next{1};

Json watch_add(uint32_t pid, uint64_t addr, size_t width, const std::string& type) {
    std::lock_guard<std::mutex> lk(g_watch_mtx);
    WatchEntry e;
    e.id = g_watch_next++;
    e.pid = pid;
    e.addr = addr;
    e.width = width ? width : 4;
    e.type = type;
    // capture the current value as the baseline so the first poll can report a change
    e.last.resize(e.width);
    if (!read_mem(pid, addr, e.last.data(), e.width)) e.last.clear();
    g_watches.push_back(std::move(e));
    Json r = Json::obj();
    r.set("id", (long long)g_watches.back().id);
    r.set("baseline", g_watches.back().last.empty() ? std::string("unreadable")
                                                    : to_hex(g_watches.back().last.data(),
                                                             g_watches.back().last.size()));
    return r;
}

Json watch_poll(int id) {
    std::lock_guard<std::mutex> lk(g_watch_mtx);
    Json r = Json::obj();
    for (auto& e : g_watches) {
        if (e.id != id) continue;
        std::vector<uint8_t> cur(e.width);
        if (!read_mem(e.pid, e.addr, cur.data(), e.width)) {
            DWORD err = 0;
            read_mem(e.pid, e.addr, cur.data(), e.width, &err);
            Json e2 = win32_error_json(err, "watch_poll read");
            e2.set("id", (long long)e.id);
            return e2;
        }
        bool changed = !e.last.empty() && std::memcmp(cur.data(), e.last.data(), e.width) != 0;
        r.set("id", (long long)e.id);
        r.set("changed", changed);
        r.set("value", to_hex(cur.data(), cur.size()));
        if (!e.last.empty()) r.set("previous", to_hex(e.last.data(), e.last.size()));

        WatchSample s;
        s.t_ms = GetTickCount64();
        s.hex = to_hex(cur.data(), cur.size());
        e.history.push_back(std::move(s));
        while (e.history.size() > kMaxWatchHistory) e.history.pop_front();
        r.set("samples", (long long)e.history.size());

        e.last = cur;
        return r;
    }
    r.set("error", "watch not found");
    return r;
}

Json watch_series(int id, size_t count) {
    std::lock_guard<std::mutex> lk(g_watch_mtx);
    Json r = Json::obj();
    for (auto& e : g_watches) {
        if (e.id != id) continue;
        r.set("id", (long long)e.id);
        r.set("total_samples", (long long)e.history.size());
        Json arr = Json::arr();
        size_t start = (count && e.history.size() > count) ? e.history.size() - count : 0;
        for (size_t k = start; k < e.history.size(); ++k) {
            Json s = Json::obj();
            s.set("t_ms", (long long)e.history[k].t_ms);
            s.set("value", e.history[k].hex);
            arr.push(std::move(s));
        }
        r.set("series", std::move(arr));
        return r;
    }
    r.set("error", "watch not found");
    return r;
}

Json watch_remove(int id) {
    std::lock_guard<std::mutex> lk(g_watch_mtx);
    for (size_t k = 0; k < g_watches.size(); ++k)
        if (g_watches[k].id == id) { g_watches.erase(g_watches.begin() + k); Json r = Json::obj(); r.set("removed", true); return r; }
    Json r = Json::obj(); r.set("removed", false); return r;
}

// =============================================================================
// PE import (IAT) hooking — no instruction relocation needed
// =============================================================================
static bool read_remote_pe(uint32_t pid, uint64_t base,
                           IMAGE_NT_HEADERS& nth, std::vector<uint8_t>& dd) {
    IMAGE_DOS_HEADER dos{};
    if (!read_mem(pid, base, &dos, sizeof(dos))) return false;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return false;
    if (!read_mem(pid, base + dos.e_lfanew, &nth, sizeof(nth))) return false;
    if (nth.Signature != IMAGE_NT_SIGNATURE) return false;
    (void)dd;
    return true;
}

struct IatSlot {
    bool found = false;
    uint64_t slot_addr = 0;   // address of the IAT entry
    uint64_t orig = 0;        // current resolved function pointer
};

static IatSlot find_iat_slot(uint32_t pid, uint64_t mod_base, const std::string& module_name,
                             const std::string& import_name) {
    IatSlot out;
    IMAGE_NT_HEADERS nth{};
    std::vector<uint8_t> dummy;
    if (!read_remote_pe(pid, mod_base, nth, dummy)) return out;

    bool is64 = nth.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    size_t ptr = is64 ? 8 : 4;
    (void)ptr;

    auto& imp_dir = nth.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (imp_dir.Size == 0) return out;

    std::string want_mod = lower(basename(module_name));
    std::string want_fn  = lower(import_name);

    uint64_t desc_addr = mod_base + imp_dir.VirtualAddress;
    for (int di = 0; di < 256; ++di) {
        IMAGE_IMPORT_DESCRIPTOR desc{};
        if (!read_mem(pid, desc_addr + di * sizeof(desc), &desc, sizeof(desc))) return out;
        if (desc.Name == 0 && desc.FirstThunk == 0) break;

        char dll_name[256] = {};
        read_mem(pid, mod_base + desc.Name, dll_name, sizeof(dll_name) - 1);
        std::string dll = lower(basename(dll_name));
        if (dll.find(want_mod) == std::string::npos) continue;

        uint64_t oft = desc.OriginalFirstThunk ? desc.OriginalFirstThunk : desc.FirstThunk;
        uint64_t thunk_addr = mod_base + oft;
        uint64_t iat_base = mod_base + desc.FirstThunk;

        for (int k = 0; k < 65536; ++k) {
            uint64_t thunk = 0;
            if (!read_mem(pid, thunk_addr + (uint64_t)k * ptr, &thunk, ptr)) return out;
            if (thunk == 0) break;

            bool by_ord = !is64 ? ((thunk & 0x80000000ull) != 0) : ((thunk & 0x8000000000000000ull) != 0);
            std::string fname;
            if (!by_ord) {
                char namebuf[256] = {};
                read_mem(pid, mod_base + thunk + 2, namebuf, sizeof(namebuf) - 1);
                fname = lower(namebuf);
            }
            if (!by_ord && fname.find(want_fn) != std::string::npos) {
                uint64_t slot = iat_base + (uint64_t)k * ptr;
                uint64_t cur = 0;
                if (!read_mem(pid, slot, &cur, ptr)) return out;
                out.found = true;
                out.slot_addr = slot;
                out.orig = cur;
                return out;
            }
        }
    }
    return out;
}

Json iat_hook(uint32_t pid, const std::string& module, const std::string& import,
              const std::vector<uint8_t>& stub) {
    Json r = Json::obj();
    auto mod = find_module(pid, module);
    if (!mod) { r.set("error", "module not loaded in target: " + module); return r; }

    IatSlot slot = find_iat_slot(pid, mod->base, mod->name, import);
    if (!slot.found) { r.set("error", "import not found: " + import); return r; }

    if (stub.empty()) { r.set("error", "empty stub"); return r; }

    uint64_t stub_addr = alloc_mem(pid, stub.size(), PAGE_EXECUTE_READWRITE);
    if (!stub_addr) { r.set("error", "stub alloc failed"); return r; }
    if (!write_mem(pid, stub_addr, stub.data(), stub.size())) { r.set("error", "stub write failed"); return r; }

    uint8_t buf[8] = {};
    std::memcpy(buf, &stub_addr, sizeof(stub_addr));
    if (!write_mem(pid, slot.slot_addr, buf, is_process_64(pid) ? 8 : 4)) {
        r.set("error", "IAT write failed");
        return r;
    }

    r.set("ok", true);
    r.set("module", mod->name);
    r.set("import", import);
    r.set("iat_slot", u64_hex(slot.slot_addr));
    r.set("original", u64_hex(slot.orig));
    r.set("stub", u64_hex(stub_addr));
    return r;
}

// =============================================================================
// speedhack — IAT hook with a generated fixed-point time-scaling stub (x64)
// =============================================================================
static void put64(std::vector<uint8_t>& v, uint64_t x) {
    for (int k = 0; k < 8; ++k) v.push_back((uint8_t)((x >> (8 * k)) & 0xFF));
}

static std::vector<uint8_t> make_scale_stub(uint64_t orig, uint64_t base, uint64_t factor,
                                            bool qpc, bool is64ret) {
    std::vector<uint8_t> s;
    if (qpc) {
        s.push_back(0x53);                                   // push rbx
        s.insert(s.end(), {0x48, 0x89, 0xCB});               // mov rbx, rcx
    }
    s.push_back(0x48); s.push_back(0xB8); put64(s, orig);    // mov rax, orig
    s.insert(s.end(), {0xFF, 0xD0});                         // call rax
    if (!is64ret && !qpc) s.insert(s.end(), {0x89, 0xC0});   // mov eax, eax
    if (qpc) { s.insert(s.end(), {0x48, 0x8B, 0x03}); }      // mov rax, [rbx]
    s.push_back(0x48); s.push_back(0xB9); put64(s, base);    // mov rcx, base
    s.insert(s.end(), {0x48, 0x29, 0xC8});                   // sub rax, rcx
    s.push_back(0x48); s.push_back(0xB9); put64(s, factor);  // mov rcx, factor
    s.insert(s.end(), {0x48, 0x0F, 0xAF, 0xC1});             // imul rax, rcx
    s.insert(s.end(), {0x48, 0xC1, 0xE8, 0x20});             // shr rax, 32
    s.push_back(0x48); s.push_back(0xB9); put64(s, base);    // mov rcx, base
    s.insert(s.end(), {0x48, 0x01, 0xC8});                   // add rax, rcx
    if (qpc) { s.insert(s.end(), {0x48, 0x89, 0x03}); }      // mov [rbx], rax
    if (qpc) { s.push_back(0x5B); }                          // pop rbx
    if (qpc) s.insert(s.end(), {0xB8, 0x01, 0x00, 0x00, 0x00}); // mov eax, 1
    s.push_back(0xC3);                                       // ret
    return s;
}

Json speedhack(uint32_t pid, double scale, const std::string& which) {
    Json r = Json::obj();
    if (!is_process_64(pid)) { r.set("error", "speedhack requires a 64-bit target"); return r; }

    std::string w = lower(which.empty() ? "qpc" : which);
    uint64_t factor = (uint64_t)(scale * 4294967296.0); // 32.32 fixed point

    LARGE_INTEGER qpc{}; QueryPerformanceCounter(&qpc);
    uint64_t base_tick = GetTickCount64();

    struct Item { const char* name; bool is_qpc; bool is64ret; uint64_t base; };
    std::vector<Item> items;
    if (w == "qpc" || w == "all")            items.push_back({"QueryPerformanceCounter", true, true, (uint64_t)qpc.QuadPart});
    if (w == "tick" || w == "all")           items.push_back({"GetTickCount", false, false, (uint64_t)(GetTickCount())});
    if (w == "tick64" || w == "all")         items.push_back({"GetTickCount64", false, true, base_tick});

    Json installed = Json::arr();
    for (auto& it : items) {
        bool done = false;
        for (auto& mod : list_modules(pid)) {
            IatSlot slot = find_iat_slot(pid, mod.base, mod.name, it.name);
            if (!slot.found || !slot.orig) continue;

            auto stub = make_scale_stub(slot.orig, it.base, factor, it.is_qpc, it.is64ret);
            uint64_t stub_addr = alloc_mem(pid, stub.size(), PAGE_EXECUTE_READWRITE);
            if (!stub_addr) continue;
            if (!write_mem(pid, stub_addr, stub.data(), stub.size())) continue;

            uint8_t buf[8] = {};
            std::memcpy(buf, &stub_addr, 8);
            if (!write_mem(pid, slot.slot_addr, buf, 8)) continue;

            Json e = Json::obj();
            e.set("function", it.name);
            e.set("module", mod.name);
            e.set("iat_slot", u64_hex(slot.slot_addr));
            e.set("stub", u64_hex(stub_addr));
            e.set("original", u64_hex(slot.orig));
            installed.push(std::move(e));
            done = true;
            break;
        }
        if (!done) {
            Json e = Json::obj();
            e.set("function", it.name);
            e.set("status", "no IAT import found (call may be inlined/dynamic)");
            installed.push(std::move(e));
        }
    }

    r.set("scale", scale);
    r.set("factor_32_32", u64_hex(factor));
    r.set("installed", std::move(installed));
    return r;
}

// =============================================================================
// memory snapshots + differential diff
// =============================================================================
struct Snapshot {
    int id;
    uint32_t pid;
    uint64_t addr;
    size_t size;
    uint64_t t_ms;
    std::vector<uint8_t> data;
};

static std::mutex g_snap_mtx;
static std::map<int, Snapshot> g_snaps;
static std::atomic<int> g_snap_next{1};

int snapshot_take(uint32_t pid, uint64_t addr, size_t size) {
    std::vector<uint8_t> buf(size);
    if (!read_mem(pid, addr, buf.data(), size)) return -1;
    Snapshot s;
    s.id = g_snap_next++;
    s.pid = pid;
    s.addr = addr;
    s.size = size;
    s.t_ms = GetTickCount64();
    s.data = std::move(buf);
    std::lock_guard<std::mutex> lk(g_snap_mtx);
    int id = s.id;
    g_snaps[id] = std::move(s);
    return id;
}

Json snapshot_diff(int id) {
    Snapshot snap;
    {
        std::lock_guard<std::mutex> lk(g_snap_mtx);
        auto it = g_snaps.find(id);
        if (it == g_snaps.end()) { Json r = Json::obj(); r.set("error", "snapshot not found"); return r; }
        snap = it->second;
    }

    std::vector<uint8_t> cur(snap.size);
    DWORD err = 0;
    if (!read_mem(snap.pid, snap.addr, cur.data(), snap.size, &err)) {
        Json r = win32_error_json(err, "snapshot_diff read");
        r.set("id", (long long)id);
        return r;
    }

    Json ranges = Json::arr();
    size_t changed_bytes = 0;
    size_t k = 0;
    while (k < snap.size) {
        if (cur[k] == snap.data[k]) { ++k; continue; }
        size_t start = k;
        while (k < snap.size && cur[k] != snap.data[k]) ++k;
        size_t len = k - start;
        changed_bytes += len;
        Json e = Json::obj();
        e.set("address", u64_hex(snap.addr + start));
        e.set("offset", (long long)start);
        e.set("length", (long long)len);
        e.set("before", to_hex(snap.data.data() + start, len));
        e.set("after", to_hex(cur.data() + start, len));
        ranges.push(std::move(e));
        if (ranges.size() >= 100000) break;
    }

    Json r = Json::obj();
    r.set("id", (long long)id);
    r.set("base", u64_hex(snap.addr));
    r.set("size", (long long)snap.size);
    r.set("changed_bytes", (long long)changed_bytes);
    r.set("changed_ranges", (long long)ranges.size());
    r.set("diff", std::move(ranges));
    return r;
}

Json snapshot_list() {
    std::lock_guard<std::mutex> lk(g_snap_mtx);
    Json arr = Json::arr();
    for (auto& kv : g_snaps) {
        Json e = Json::obj();
        e.set("id", (long long)kv.second.id);
        e.set("pid", (long long)kv.second.pid);
        e.set("address", u64_hex(kv.second.addr));
        e.set("size", (long long)kv.second.size);
        e.set("t_ms", (long long)kv.second.t_ms);
        arr.push(std::move(e));
    }
    Json r = Json::obj();
    r.set("count", (long long)arr.size());
    r.set("snapshots", std::move(arr));
    return r;
}

// =============================================================================
// background thread (keeps frozen values pinned)
// =============================================================================
static std::atomic<bool> g_running{false};
static std::thread g_thread;

void runtime_start() {
    if (g_running.exchange(true)) return;
    g_thread = std::thread([]() {
        while (g_running.load()) {
            {
                std::lock_guard<std::mutex> lk(g_freeze_mtx);
                for (auto& e : g_freezes) {
                    if (e.active && !e.data.empty())
                        write_mem(e.pid, e.addr, e.data.data(), e.data.size());
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(8));
        }
    });
}

void runtime_stop() {
    if (!g_running.exchange(false)) return;
    if (g_thread.joinable()) g_thread.join();
}

} // namespace cmcp
