#include "cheatmcp.hpp"

#include <fstream>
#include <cstring>
#include <cstdio>
#include <algorithm>

namespace cmcp {

// =============================================================================
// schema helpers
// =============================================================================
static Json prop(const std::string& type, const std::string& desc) {
    Json j = Json::obj();
    j.set("type", type);
    j.set("description", desc);
    return j;
}

static Json schema(Json props, std::vector<std::string> required = {}) {
    if (!props.is_obj()) props = Json::obj();
    Json s = Json::obj();
    s.set("type", "object");
    s.set("properties", std::move(props));
    Json req = Json::arr();
    for (auto& r : required) req.push(r);
    s.set("required", std::move(req));
    return s;
}

static ToolResult ok(Json j) {
    ToolResult r;
    r.is_error = false;
    r.structured = j;
    r.text = j.dump();
    return r;
}

static ToolResult fail(const std::string& msg) {
    ToolResult r;
    r.is_error = true;
    Json j = Json::obj();
    j.set("error", msg);
    r.structured = j;
    r.text = j.dump();
    return r;
}

static void reg(const char* name, const char* desc, Json s, ToolFn fn) {
    registry().add(name, desc, std::move(s), std::move(fn));
}

static ScanType stype(const std::string& s) {
    std::string v = lower(s);
    if (v == "i8"  || v == "byte")   return ScanType::I8;
    if (v == "i16" || v == "short")  return ScanType::I16;
    if (v == "i32" || v == "int")    return ScanType::I32;
    if (v == "i64" || v == "int64")  return ScanType::I64;
    if (v == "f32" || v == "float")  return ScanType::F32;
    if (v == "f64" || v == "double") return ScanType::F64;
    if (v == "str" || v == "string") return ScanType::Str;
    if (v == "aob" || v == "bytes")  return ScanType::Aob;
    return ScanType::I32;
}

static DWORD protect_from_string(const std::string& s) {
    std::string v = lower(s);
    if (v == "r"   || v == "read")      return PAGE_READONLY;
    if (v == "rw"  || v == "readwrite") return PAGE_READWRITE;
    if (v == "rx"  || v == "execute")   return PAGE_EXECUTE_READ;
    if (v == "rwx" || v == "all")       return PAGE_EXECUTE_READWRITE;
    if (v == "x")                       return PAGE_EXECUTE;
    if (v == "wc")                      return PAGE_WRITECOPY;
    try { return (DWORD)std::stoul(s, nullptr, 0); } catch (...) { return PAGE_READWRITE; }
}

static std::string protect_to_string(DWORD p) {
    if (p & PAGE_GUARD) p &= ~PAGE_GUARD;
    switch (p & 0xFF) {
        case PAGE_NOACCESS:          return "NOACCESS";
        case PAGE_READONLY:          return "R";
        case PAGE_READWRITE:         return "RW";
        case PAGE_WRITECOPY:         return "WC";
        case PAGE_EXECUTE:           return "X";
        case PAGE_EXECUTE_READ:      return "RX";
        case PAGE_EXECUTE_READWRITE: return "RWX";
        case PAGE_EXECUTE_WRITECOPY: return "XWC";
        default:                     return "?";
    }
}

static bool is_admin() {
    BOOL admin = FALSE;
    PSID grp = nullptr;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &grp)) {
        CheckTokenMembership(nullptr, grp, &admin);
        FreeSid(grp);
    }
    return admin != FALSE;
}

static uint32_t require_pid(const Json& a) {
    if (a.has("pid")) return (uint32_t)parse_u64(a.at("pid"));
    for (const char* key : { "process", "name" }) {
        if (a.has(key)) {
            auto p = find_process(a.at(key).as_s());
            if (p) return p->pid;
        }
    }
    return 0;
}

// =============================================================================
// registration
// =============================================================================
void register_all_tools() {
    // ---------------------------------------------------------------- system
    reg("enable_privilege", "Enable SeDebugPrivilege (needed to touch most games).",
        schema(Json::obj()),
        [](const Json&) {
            bool okp = enable_debug_privilege();
            Json j = Json::obj(); j.set("debug_privilege", okp); return ok(j);
        });

    reg("system_info", "OS version, architecture, elevation and privilege status.",
        schema(Json::obj()),
        [](const Json&) {
            Json j = Json::obj();
            j.set("architecture", sizeof(void*) == 8 ? "x64" : "x86");
            j.set("is_admin", is_admin());
            j.set("debug_privilege_enabled", enable_debug_privilege());
            Json os = Json::obj();
            OSVERSIONINFOEXA v{}; v.dwOSVersionInfoSize = sizeof(v);
#pragma warning(suppress : 4996)
            GetVersionExA((OSVERSIONINFOA*)&v);
            os.set("major", (long long)v.dwMajorVersion);
            os.set("minor", (long long)v.dwMinorVersion);
            os.set("build", (long long)v.dwBuildNumber);
            j.set("os", std::move(os));
            return ok(j);
        });

    reg("convert", "Convert values between hex/decimal and decode byte buffers.",
        schema(Json::obj(), {}),
        [](const Json& a) {
            Json j = Json::obj();
            if (a.has("hex")) {
                auto b = parse_hex(a.at("hex").as_s());
                j.set("bytes", (long long)b.size());
                uint64_t v = 0;
                for (size_t k = 0; k < b.size() && k < 8; ++k) v |= (uint64_t)b[k] << (8 * k);
                j.set("as_u64_le", u64_hex(v));
                j.set("as_i64_le", (long long)v);
            }
            if (a.has("value")) {
                uint64_t v = parse_u64(a.at("value"));
                j.set("hex", u64_hex(v));
                j.set("dec", (long long)v);
            }
            return ok(j);
        });

    // ---------------------------------------------------------------- process
    reg("process_list", "List running processes (pid, ppid, name, path).",
        schema({ {"filter", prop("string", "optional name substring filter")} }),
        [](const Json& a) {
            std::string f = a.has("filter") ? lower(a.at("filter").as_s()) : "";
            Json arr = Json::arr();
            for (auto& p : list_processes()) {
                if (!f.empty() && lower(p.name).find(f) == std::string::npos) continue;
                Json e = Json::obj();
                e.set("pid", (long long)p.pid);
                e.set("ppid", (long long)p.ppid);
                e.set("name", p.name);
                e.set("path", p.path);
                e.set("wow64", p.wow64);
                arr.push(std::move(e));
            }
            Json j = Json::obj();
            j.set("count", (long long)arr.size());
            j.set("processes", std::move(arr));
            return ok(j);
        });

    reg("process_open", "Open a handle to a process by pid or name (cached).",
        schema({ {"pid", prop("integer", "process id")}, {"name", prop("string", "process name")} }),
        [](const Json& a) {
            uint32_t pid = require_pid(a);
            if (!pid) return fail("pid or name required");
            HANDLE h = get_handle(pid);
            Json j = Json::obj();
            j.set("pid", (long long)pid);
            j.set("opened", h != nullptr);
            j.set("is_64bit", h ? is_process_64(pid) : false);
            return ok(j);
        });

    reg("process_close", "Close and forget the cached handle for a process.",
        schema({ {"pid", prop("integer", "process id")} }, {"pid"}),
        [](const Json& a) {
            uint32_t pid = (uint32_t)parse_u64(a.at("pid"));
            drop_handle(pid);
            Json j = Json::obj(); j.set("closed", true); return ok(j);
        });

    reg("process_info", "Basic information about a process.",
        schema({ {"pid", prop("integer", "")} }, {"pid"}),
        [](const Json& a) {
            uint32_t pid = (uint32_t)parse_u64(a.at("pid"));
            HANDLE h = get_handle(pid);
            Json j = Json::obj();
            j.set("pid", (long long)pid);
            j.set("opened", h != nullptr);
            j.set("is_64bit", is_process_64(pid));
            char path[MAX_PATH * 2] = {};
            DWORD sz = sizeof(path) - 1;
            if (h && QueryFullProcessImageNameA(h, 0, path, &sz)) j.set("path", path);
            DWORD code = 0;
            if (h && GetExitCodeProcess(h, &code)) j.set("exit_code", (long long)code);
            auto mods = list_modules(pid);
            j.set("module_count", (long long)mods.size());
            return ok(j);
        });

    reg("process_threads", "List thread ids belonging to a process.",
        schema({ {"pid", prop("integer", "")} }, {"pid"}),
        [](const Json& a) {
            uint32_t pid = (uint32_t)parse_u64(a.at("pid"));
            Json arr = Json::arr();
            for (auto& t : list_threads(pid)) arr.push((long long)t.first);
            Json j = Json::obj();
            j.set("tid_list", std::move(arr));
            return ok(j);
        });

    reg("process_windows", "Enumerate top-level windows owned by a process.",
        schema({ {"pid", prop("integer", "")} }, {"pid"}),
        [](const Json& a) {
            uint32_t pid = (uint32_t)parse_u64(a.at("pid"));
            struct Ctx { uint32_t pid; Json* arr; } ctx{ pid, nullptr };
            Json arr = Json::arr();
            ctx.arr = &arr;
            EnumWindows([](HWND hwnd, LPARAM lp) -> BOOL {
                auto* c = (Ctx*)lp;
                DWORD wpid = 0;
                GetWindowThreadProcessId(hwnd, &wpid);
                if (wpid == c->pid) {
                    char title[256] = {}, cls[256] = {};
                    GetWindowTextA(hwnd, title, sizeof(title) - 1);
                    GetClassNameA(hwnd, cls, sizeof(cls) - 1);
                    Json e = Json::obj();
                    e.set("hwnd", u64_hex((uint64_t)(uintptr_t)hwnd));
                    e.set("title", title);
                    e.set("class", cls);
                    e.set("visible", IsWindowVisible(hwnd) != FALSE);
                    c->arr->push(std::move(e));
                }
                return TRUE;
            }, (LPARAM)&ctx);
            Json j = Json::obj();
            j.set("count", (long long)arr.size());
            j.set("windows", std::move(arr));
            return ok(j);
        });

    // ---------------------------------------------------------------- modules
    reg("module_list", "List loaded modules (name, base, size, path).",
        schema({ {"pid", prop("integer", "")} }, {"pid"}),
        [](const Json& a) {
            uint32_t pid = (uint32_t)parse_u64(a.at("pid"));
            Json arr = Json::arr();
            for (auto& m : list_modules(pid)) {
                Json e = Json::obj();
                e.set("name", m.name);
                e.set("base", u64_hex(m.base));
                e.set("size", u64_hex(m.size));
                e.set("end", u64_hex(m.base + m.size));
                e.set("path", m.path);
                arr.push(std::move(e));
            }
            Json j = Json::obj();
            j.set("count", (long long)arr.size());
            j.set("modules", std::move(arr));
            return ok(j);
        });

    reg("module_base", "Resolve the base address of a module by name.",
        schema({ {"pid", prop("integer", "")}, {"name", prop("string", "")} }, {"pid", "name"}),
        [](const Json& a) {
            uint32_t pid = (uint32_t)parse_u64(a.at("pid"));
            auto m = find_module(pid, a.at("name").as_s());
            if (!m) return fail("module not found");
            Json j = Json::obj();
            j.set("name", m->name);
            j.set("base", u64_hex(m->base));
            j.set("size", u64_hex(m->size));
            return ok(j);
        });

    reg("module_resolve", "Resolve module+offset (or export) into an absolute address.",
        schema({ {"pid", prop("integer", "")}, {"module", prop("string", "")},
                  {"offset", prop("string", "hex or dec offset")},
                  {"export", prop("string", "optional export name")} }, {"pid", "module"}),
        [](const Json& a) {
            uint32_t pid = (uint32_t)parse_u64(a.at("pid"));
            std::string mod = a.at("module").as_s();
            auto m = find_module(pid, mod);
            if (!m) return fail("module not found");

            uint64_t addr = m->base;
            if (a.has("offset")) addr += parse_u64(a.at("offset"));
            if (a.has("export")) {
                HMODULE hm = LoadLibraryA(mod.c_str());
                if (hm) {
                    auto fn = (uint64_t)(uintptr_t)GetProcAddress(hm, a.at("export").as_s().c_str());
                    if (fn) addr = m->base + (fn - (uint64_t)(uintptr_t)hm);
                }
            }
            Json j = Json::obj();
            j.set("address", u64_hex(addr));
            return ok(j);
        });

    // ---------------------------------------------------------------- memory
    reg("memory_read", "Read memory from a process (hex + optional typed decode).",
        schema({ {"pid", prop("integer", "")}, {"address", prop("string", "")},
                  {"size", prop("integer", "bytes to read (default 256)")},
                  {"type", prop("string", "optional i32/i64/f32/f64/i8/i16")} },
               {"pid", "address"}),
        [](const Json& a) {
            uint32_t pid = (uint32_t)parse_u64(a.at("pid"));
            uint64_t addr = parse_u64(a.at("address"));
            size_t n = a.has("size") ? (size_t)parse_u64(a.at("size")) : 256;
            if (n == 0 || n > (1 << 20)) n = 256;
            std::vector<uint8_t> buf(n);
            if (!read_mem(pid, addr, buf.data(), n)) return fail("read failed");
            Json j = Json::obj();
            j.set("address", u64_hex(addr));
            j.set("size", (long long)n);
            j.set("hex", to_hex(buf.data(), n));
            if (a.has("type")) {
                std::string t = lower(a.at("type").as_s());
                if (t == "i32" && n >= 4) { int32_t v; std::memcpy(&v, buf.data(), 4); j.set("i32", (long long)v); }
                else if (t == "i64" && n >= 8) { int64_t v; std::memcpy(&v, buf.data(), 8); j.set("i64", (long long)v); }
                else if (t == "i16" && n >= 2) { int16_t v; std::memcpy(&v, buf.data(), 2); j.set("i16", (long long)v); }
                else if (t == "i8"  && n >= 1) { j.set("i8", (long long)(int8_t)buf[0]); }
                else if (t == "f32" && n >= 4) { float v; std::memcpy(&v, buf.data(), 4); j.set("f32", (double)v); }
                else if (t == "f64" && n >= 8) { double v; std::memcpy(&v, buf.data(), 8); j.set("f64", v); }
            }
            return ok(j);
        });

    reg("memory_write", "Write raw bytes (hex) into process memory.",
        schema({ {"pid", prop("integer", "")}, {"address", prop("string", "")},
                  {"data", prop("string", "hex bytes, e.g. '48 8B 05'")} }, {"pid", "address", "data"}),
        [](const Json& a) {
            uint32_t pid = (uint32_t)parse_u64(a.at("pid"));
            uint64_t addr = parse_u64(a.at("address"));
            auto bytes = parse_hex(a.at("data").as_s());
            if (bytes.empty()) return fail("no bytes");
            bool okw = write_mem(pid, addr, bytes.data(), bytes.size());
            Json j = Json::obj();
            j.set("written", okw);
            j.set("bytes", (long long)bytes.size());
            return okw ? ok(j) : fail("write failed");
        });

    reg("memory_alloc", "Allocate memory inside the target process.",
        schema({ {"pid", prop("integer", "")}, {"size", prop("integer", "")},
                  {"protect", prop("string", "rwx|rw|rx|r")} }, {"pid", "size"}),
        [](const Json& a) {
            uint32_t pid = (uint32_t)parse_u64(a.at("pid"));
            size_t n = (size_t)parse_u64(a.at("size"));
            DWORD p = a.has("protect") ? protect_from_string(a.at("protect").as_s()) : PAGE_READWRITE;
            uint64_t addr = alloc_mem(pid, n, p);
            if (!addr) return fail("alloc failed");
            Json j = Json::obj(); j.set("address", u64_hex(addr)); return ok(j);
        });

    reg("memory_free", "Free memory previously allocated in the target.",
        schema({ {"pid", prop("integer", "")}, {"address", prop("string", "")} }, {"pid", "address"}),
        [](const Json& a) {
            uint32_t pid = (uint32_t)parse_u64(a.at("pid"));
            bool okf = free_mem(pid, parse_u64(a.at("address")));
            Json j = Json::obj(); j.set("freed", okf); return ok(j);
        });

    reg("memory_protect", "Change page protection inside the target process.",
        schema({ {"pid", prop("integer", "")}, {"address", prop("string", "")},
                  {"size", prop("integer", "")}, {"protect", prop("string", "rwx|rw|rx|r")} },
               {"pid", "address", "size", "protect"}),
        [](const Json& a) {
            uint32_t pid = (uint32_t)parse_u64(a.at("pid"));
            uint32_t oldp = 0;
            bool okp = protect_mem(pid, parse_u64(a.at("address")), (size_t)parse_u64(a.at("size")),
                                   protect_from_string(a.at("protect").as_s()), &oldp);
            Json j = Json::obj();
            j.set("changed", okp);
            j.set("old", protect_to_string(oldp));
            return ok(j);
        });

    reg("memory_regions", "Dump virtual memory regions (VirtualQueryEx).",
        schema({ {"pid", prop("integer", "")}, {"start", prop("string", "")}, {"end", prop("string", "")} },
               {"pid"}),
        [](const Json& a) {
            uint32_t pid = (uint32_t)parse_u64(a.at("pid"));
            uint64_t s = a.has("start") ? parse_u64(a.at("start")) : 0;
            uint64_t e = a.has("end") ? parse_u64(a.at("end")) : ~0ull;
            Json arr = Json::arr();
            for (auto& m : query_regions(pid, s, e)) {
                Json j = Json::obj();
                j.set("base", u64_hex((uint64_t)(uintptr_t)m.BaseAddress));
                j.set("size", u64_hex((uint64_t)m.RegionSize));
                j.set("protect", protect_to_string(m.Protect));
                j.set("state", (long long)m.State);
                j.set("type", m.Type == MEM_IMAGE ? "image" : m.Type == MEM_MAPPED ? "mapped" : "private");
                arr.push(std::move(j));
            }
            Json j = Json::obj();
            j.set("count", (long long)arr.size());
            j.set("regions", std::move(arr));
            return ok(j);
        });

    reg("memory_dump", "Dump a region of target memory to a local file.",
        schema({ {"pid", prop("integer", "")}, {"address", prop("string", "")},
                  {"size", prop("integer", "")}, {"path", prop("string", "")} },
               {"pid", "address", "size", "path"}),
        [](const Json& a) {
            uint32_t pid = (uint32_t)parse_u64(a.at("pid"));
            uint64_t addr = parse_u64(a.at("address"));
            size_t n = (size_t)parse_u64(a.at("size"));
            std::string path = a.at("path").as_s();
            std::vector<uint8_t> buf(n);
            if (!read_mem(pid, addr, buf.data(), n)) return fail("read failed");
            std::ofstream f(path, std::ios::binary);
            if (!f) return fail("cannot open output file");
            f.write((const char*)buf.data(), (std::streamsize)n);
            Json j = Json::obj();
            j.set("path", path);
            j.set("bytes", (long long)n);
            return ok(j);
        });

    reg("pointer_read", "Follow a multi-level pointer chain (module/address + offsets).",
        schema({ {"pid", prop("integer", "")}, {"module", prop("string", "base module (or use base)")},
                  {"base", prop("string", "absolute base address (alternative to module)")},
                  {"offsets", prop("array", "list of offsets applied in order")} }, {"pid"}),
        [](const Json& a) {
            uint32_t pid = (uint32_t)parse_u64(a.at("pid"));
            uint64_t cur = 0;
            if (a.has("module")) {
                auto m = find_module(pid, a.at("module").as_s());
                if (!m) return fail("module not found");
                cur = m->base;
            } else if (a.has("base")) {
                cur = parse_u64(a.at("base"));
            } else return fail("module or base required");

            size_t ptr = is_process_64(pid) ? 8 : 4;
            if (a.has("offsets")) {
                for (auto& off : a.at("offsets").a) {
                    cur += parse_u64(off);
                    uint64_t next = 0;
                    if (!read_mem(pid, cur, &next, ptr)) { Json j = Json::obj(); j.set("error", "read failed"); j.set("address", u64_hex(cur)); return ok(j); }
                    cur = next;
                }
            }
            Json j = Json::obj();
            j.set("address", u64_hex(cur));
            return ok(j);
        });

    // ---------------------------------------------------------------- scanner
    reg("scan_value", "First value scan across the target's memory.",
        schema({ {"pid", prop("integer", "")}, {"type", prop("string", "i8|i16|i32|i64|f32|f64|str")},
                  {"value", prop("string", "")},
                  {"writable_only", prop("boolean", "default true")},
                  {"max_hits", prop("integer", "default 1000000")} }, {"pid", "type", "value"}),
        [](const Json& a) {
            uint32_t pid = (uint32_t)parse_u64(a.at("pid"));
            bool wo = a.has("writable_only") ? a.at("writable_only").as_b() : true;
            size_t maxh = a.has("max_hits") ? (size_t)parse_u64(a.at("max_hits")) : 1000000;
            size_t n = scan_first(pid, stype(a.at("type").as_s()), a.at("value").as_s(), wo, maxh);
            Json j = Json::obj();
            j.set("hits", (long long)n);
            return ok(j);
        });

    reg("scan_aob", "Array-of-bytes signature scan (supports ?? wildcards).",
        schema({ {"pid", prop("integer", "")}, {"pattern", prop("string", "e.g. '48 8B ?? ? ? C3'")},
                  {"writable_only", prop("boolean", "default false")},
                  {"max_hits", prop("integer", "")} }, {"pid", "pattern"}),
        [](const Json& a) {
            uint32_t pid = (uint32_t)parse_u64(a.at("pid"));
            bool wo = a.has("writable_only") ? a.at("writable_only").as_b() : false;
            size_t maxh = a.has("max_hits") ? (size_t)parse_u64(a.at("max_hits")) : 1000;
            size_t n = scan_aob(pid, a.at("pattern").as_s(), wo, maxh);
            Json j = Json::obj(); j.set("hits", (long long)n); return ok(j);
        });

    reg("scan_refine", "Next-scan: filter previous results (exact/changed/unchanged/increased/decreased).",
        schema({ {"pid", prop("integer", "")}, {"mode", prop("string", "")}, {"value", prop("string", "")} },
               {"pid", "mode"}),
        [](const Json& a) {
            uint32_t pid = (uint32_t)parse_u64(a.at("pid"));
            size_t n = scan_refine(pid, a.at("mode").as_s(),
                                   a.has("value") ? a.at("value").as_s() : "");
            Json j = Json::obj(); j.set("hits", (long long)n); return ok(j);
        });

    reg("scan_results", "Return current scan results (paginated, with live values).",
        schema({ {"pid", prop("integer", "")}, {"offset", prop("integer", "")},
                  {"limit", prop("integer", "default 100")}, {"type", prop("string", "")} }),
        [](const Json& a) {
            uint32_t pid = a.has("pid") ? (uint32_t)parse_u64(a.at("pid")) : 0;
            size_t off = a.has("offset") ? (size_t)parse_u64(a.at("offset")) : 0;
            size_t lim = a.has("limit") ? (size_t)parse_u64(a.at("limit")) : 100;
            return ok(scan_results(off, lim, pid, a.has("type") ? a.at("type").as_s() : ""));
        });

    reg("scan_reset", "Clear the current scan session.", schema(Json::obj()),
        [](const Json&) { scan_reset(); Json j = Json::obj(); j.set("reset", true); return ok(j); });

    reg("pointer_scan", "Reverse pointer scan: find addresses pointing near a target.",
        schema({ {"pid", prop("integer", "")}, {"address", prop("string", "")},
                  {"max_offset", prop("integer", "default 0x1000")},
                  {"max_results", prop("integer", "default 500")} }, {"pid", "address"}),
        [](const Json& a) {
            uint32_t pid = (uint32_t)parse_u64(a.at("pid"));
            size_t mo = a.has("max_offset") ? (size_t)parse_u64(a.at("max_offset")) : 0x1000;
            size_t mr = a.has("max_results") ? (size_t)parse_u64(a.at("max_results")) : 500;
            return ok(pointer_scan(pid, parse_u64(a.at("address")), mo, mr));
        });

    // ---------------------------------------------------------------- patching
    reg("patch_bytes", "Patch code/data with raw bytes (auto-lifts page protection).",
        schema({ {"pid", prop("integer", "")}, {"address", prop("string", "")},
                  {"data", prop("string", "hex")} }, {"pid", "address", "data"}),
        [](const Json& a) {
            uint32_t pid = (uint32_t)parse_u64(a.at("pid"));
            auto bytes = parse_hex(a.at("data").as_s());
            bool okw = write_mem(pid, parse_u64(a.at("address")), bytes.data(), bytes.size());
            Json j = Json::obj(); j.set("patched", okw); return ok(j);
        });

    reg("patch_nop", "Write NOP (0x90) sled over a range — disables instructions.",
        schema({ {"pid", prop("integer", "")}, {"address", prop("string", "")},
                  {"size", prop("integer", "")} }, {"pid", "address", "size"}),
        [](const Json& a) {
            uint32_t pid = (uint32_t)parse_u64(a.at("pid"));
            size_t n = (size_t)parse_u64(a.at("size"));
            std::vector<uint8_t> nops(n, 0x90);
            bool okw = write_mem(pid, parse_u64(a.at("address")), nops.data(), nops.size());
            Json j = Json::obj(); j.set("noped", (long long)n); j.set("ok", okw); return ok(j);
        });

    reg("patch_string", "Overwrite memory with an ASCII/UTF-8 string.",
        schema({ {"pid", prop("integer", "")}, {"address", prop("string", "")},
                  {"text", prop("string", "")}, {"wide", prop("boolean", "")} }, {"pid", "address", "text"}),
        [](const Json& a) {
            uint32_t pid = (uint32_t)parse_u64(a.at("pid"));
            std::string t = a.at("text").as_s();
            std::vector<uint8_t> bytes;
            if (a.has("wide") && a.at("wide").as_b()) {
                for (char c : t) { bytes.push_back((uint8_t)c); bytes.push_back(0); }
                bytes.push_back(0); bytes.push_back(0);
            } else {
                bytes.assign(t.begin(), t.end());
            }
            bool okw = write_mem(pid, parse_u64(a.at("address")), bytes.data(), bytes.size());
            Json j = Json::obj(); j.set("ok", okw); return ok(j);
        });

    // ---------------------------------------------------------------- injection
    reg("inject_dll", "Inject a DLL using loadlibrary|nt|hijack|apc|wndhook|manualmap.",
        schema({ {"pid", prop("integer", "")}, {"path", prop("string", "absolute dll path")},
                  {"method", prop("string", "default loadlibrary")} }, {"pid", "path"}),
        [](const Json& a) {
            uint32_t pid = (uint32_t)parse_u64(a.at("pid"));
            std::string method = a.has("method") ? a.at("method").as_s() : "loadlibrary";
            auto r = inject_dll(pid, a.at("path").as_s(), method);
            Json j = Json::obj();
            j.set("ok", r.ok);
            j.set("result", u64_hex(r.value));
            j.set("method", method);
            if (!r.error.empty()) j.set("error", r.error);
            return r.ok ? ok(j) : fail(r.error);
        });

    reg("eject_dll", "Unload a DLL from the target via remote FreeLibrary.",
        schema({ {"pid", prop("integer", "")}, {"address", prop("string", "module base")},
                  {"module", prop("string", "or module name")} }, {"pid"}),
        [](const Json& a) {
            uint32_t pid = (uint32_t)parse_u64(a.at("pid"));
            uint64_t base = a.has("address") ? parse_u64(a.at("address")) : 0;
            if (!base && a.has("module")) {
                auto m = find_module(pid, a.at("module").as_s());
                if (!m) return fail("module not found");
                base = m->base;
            }
            std::string err;
            bool okx = eject_dll(pid, base, err);
            return okx ? ok(Json::obj()) : fail(err);
        });

    reg("inject_shellcode", "Write executable shellcode into the target and run it.",
        schema({ {"pid", prop("integer", "")}, {"code", prop("string", "hex shellcode")} },
               {"pid", "code"}),
        [](const Json& a) {
            uint32_t pid = (uint32_t)parse_u64(a.at("pid"));
            auto r = inject_shellcode(pid, parse_hex(a.at("code").as_s()));
            Json j = Json::obj();
            j.set("ok", r.ok);
            j.set("address", u64_hex(r.value));
            if (!r.error.empty()) j.set("error", r.error);
            return r.ok ? ok(j) : fail(r.error);
        });

    reg("execute_remote", "Call a function address inside the target with one argument.",
        schema({ {"pid", prop("integer", "")}, {"function", prop("string", "absolute address")},
                  {"arg", prop("string", "argument (default 0)")} }, {"pid", "function"}),
        [](const Json& a) {
            uint32_t pid = (uint32_t)parse_u64(a.at("pid"));
            uint64_t fn = parse_u64(a.at("function"));
            uint64_t arg = a.has("arg") ? parse_u64(a.at("arg")) : 0;
            auto r = run_remote(pid, fn, arg);
            Json j = Json::obj();
            j.set("ok", r.ok);
            j.set("return", u64_hex(r.value));
            if (!r.error.empty()) j.set("error", r.error);
            return r.ok ? ok(j) : fail(r.error);
        });

    reg("call_export", "Call an exported function (by name) inside the target.",
        schema({ {"pid", prop("integer", "")}, {"module", prop("string", "")},
                  {"export", prop("string", "")}, {"arg", prop("string", "")} },
               {"pid", "module", "export"}),
        [](const Json& a) {
            uint32_t pid = (uint32_t)parse_u64(a.at("pid"));
            std::string mod = a.at("module").as_s();
            auto tm = find_module(pid, mod);
            if (!tm) return fail("module not loaded in target");
            HMODULE hm = LoadLibraryA(mod.c_str());
            if (!hm) return fail("cannot load module locally");
            auto fn = (uint64_t)(uintptr_t)GetProcAddress(hm, a.at("export").as_s().c_str());
            if (!fn) return fail("export not found");
            uint64_t remote_fn = tm->base + (fn - (uint64_t)(uintptr_t)hm);
            uint64_t arg = a.has("arg") ? parse_u64(a.at("arg")) : 0;
            auto r = run_remote(pid, remote_fn, arg);
            Json j = Json::obj();
            j.set("ok", r.ok);
            j.set("remote_function", u64_hex(remote_fn));
            j.set("return", u64_hex(r.value));
            return r.ok ? ok(j) : fail(r.error);
        });

    // ---------------------------------------------------------------- anticheat
    reg("ac_detect", "Detect anti-cheat modules/drivers associated with a process.",
        schema({ {"pid", prop("integer", "")} }, {"pid"}),
        [](const Json& a) { return ok(ac_detect((uint32_t)parse_u64(a.at("pid")))); });

    reg("ac_kernel_drivers", "List kernel drivers and flag known anti-cheat ones.",
        schema(Json::obj()),
        [](const Json&) { return ok(ac_kernel_drivers()); });

    reg("ac_check_debug", "Check debugger presence for self and target process.",
        schema({ {"pid", prop("integer", "")} }, {"pid"}),
        [](const Json& a) { return ok(ac_check_debug((uint32_t)parse_u64(a.at("pid")))); });

    reg("ac_list_handles", "List handles other processes hold to the target.",
        schema({ {"pid", prop("integer", "")} }, {"pid"}),
        [](const Json& a) { return ok(ac_list_handles((uint32_t)parse_u64(a.at("pid")))); });

    reg("ac_close_handles", "Strip (close) foreign handles pointing at the target process.",
        schema({ {"pid", prop("integer", "")} }, {"pid"}),
        [](const Json& a) {
            size_t n = ac_close_handles((uint32_t)parse_u64(a.at("pid")));
            Json j = Json::obj(); j.set("closed", (long long)n); return ok(j);
        });

    // ---------------------------------------------------------------- network
    reg("net_connections", "List TCP/UDP connections with owning pid.",
        schema({ {"pid", prop("integer", "filter by pid (-1 = all)")} }),
        [](const Json& a) {
            int pf = a.has("pid") ? (int)parse_u64(a.at("pid")) : -1;
            return ok(net_connections(pf));
        });

    reg("net_resolve", "Resolve a hostname to IP addresses.",
        schema({ {"host", prop("string", "")} }, {"host"}),
        [](const Json& a) { return ok(net_resolve(a.at("host").as_s())); });

    reg("net_send_udp", "Send a UDP datagram (payload as hex).",
        schema({ {"host", prop("string", "")}, {"port", prop("integer", "")},
                  {"data", prop("string", "hex payload")} }, {"host", "port", "data"}),
        [](const Json& a) {
            std::string err;
            bool okx = net_send_udp(a.at("host").as_s(), (uint16_t)parse_u64(a.at("port")),
                                    parse_hex(a.at("data").as_s()), err);
            return okx ? ok(Json::obj()) : fail(err);
        });

    reg("net_send_tcp", "Send a TCP payload to host:port.",
        schema({ {"host", prop("string", "")}, {"port", prop("integer", "")},
                  {"data", prop("string", "hex payload")} }, {"host", "port", "data"}),
        [](const Json& a) {
            std::string err;
            bool okx = net_send_tcp(a.at("host").as_s(), (uint16_t)parse_u64(a.at("port")),
                                    parse_hex(a.at("data").as_s()), err);
            return okx ? ok(Json::obj()) : fail(err);
        });

    reg("net_capture", "Capture raw IP packets (SIO_RCVALL — needs admin).",
        schema({ {"filter_ip", prop("string", "only packets to/from this IP")},
                  {"max_packets", prop("integer", "")}, {"timeout_ms", prop("integer", "")} }),
        [](const Json& a) {
            std::string f = a.has("filter_ip") ? a.at("filter_ip").as_s() : "";
            int mp = a.has("max_packets") ? (int)parse_u64(a.at("max_packets")) : 20;
            int to = a.has("timeout_ms") ? (int)parse_u64(a.at("timeout_ms")) : 1500;
            return ok(net_capture(f, mp, to));
        });

    reg("net_send_raw_ip", "Send a raw IP packet (IP_HDRINCL, spoof-capable, admin).",
        schema({ {"dst_ip", prop("string", "numeric IPv4 bytes, e.g. 0x0100007F")},
                  {"packet", prop("string", "full hex IP packet")} }, {"dst_ip", "packet"}),
        [](const Json& a) {
            uint32_t dst = (uint32_t)parse_u64(a.at("dst_ip"));
            return ok(net_send_raw_ip(dst, parse_hex(a.at("packet").as_s())));
        });

    // ---------------------------------------------------------------- runtime
    reg("freeze_add", "Freeze a memory value (rewritten continuously in background).",
        schema({ {"pid", prop("integer", "")}, {"address", prop("string", "")},
                  {"data", prop("string", "hex bytes")} }, {"pid", "address", "data"}),
        [](const Json& a) {
            return ok(freeze_add((uint32_t)parse_u64(a.at("pid")), parse_u64(a.at("address")),
                                 parse_hex(a.at("data").as_s())));
        });

    reg("freeze_remove", "Remove a freeze by id.",
        schema({ {"id", prop("integer", "")} }, {"id"}),
        [](const Json& a) { return ok(freeze_remove((int)parse_u64(a.at("id")))); });

    reg("freeze_list", "List active freezes.", schema(Json::obj()),
        [](const Json&) { return ok(freeze_list()); });

    reg("watch_add", "Watch a memory value and detect changes on poll.",
        schema({ {"pid", prop("integer", "")}, {"address", prop("string", "")},
                  {"width", prop("integer", "default 4")}, {"type", prop("string", "")} },
               {"pid", "address"}),
        [](const Json& a) {
            size_t w = a.has("width") ? (size_t)parse_u64(a.at("width")) : 4;
            return ok(watch_add((uint32_t)parse_u64(a.at("pid")), parse_u64(a.at("address")),
                                w, a.has("type") ? a.at("type").as_s() : ""));
        });

    reg("watch_poll", "Poll a watch: returns value and whether it changed.",
        schema({ {"id", prop("integer", "")} }, {"id"}),
        [](const Json& a) { return ok(watch_poll((int)parse_u64(a.at("id")))); });

    reg("watch_remove", "Remove a watch by id.",
        schema({ {"id", prop("integer", "")} }, {"id"}),
        [](const Json& a) { return ok(watch_remove((int)parse_u64(a.at("id")))); });

    reg("iat_hook", "Redirect an imported function via IAT hooking (no code relocation).",
        schema({ {"pid", prop("integer", "")}, {"module", prop("string", "module owning the import")},
                  {"import", prop("string", "imported function name")},
                  {"stub", prop("string", "hex of the stub to redirect to")} },
               {"pid", "module", "import", "stub"}),
        [](const Json& a) {
            return ok(iat_hook((uint32_t)parse_u64(a.at("pid")), a.at("module").as_s(),
                               a.at("import").as_s(), parse_hex(a.at("stub").as_s())));
        });

    reg("speedhack", "Install a time-scaling IAT hook (qpc|tick|tick64|all).",
        schema({ {"pid", prop("integer", "")}, {"scale", prop("number", "e.g. 2.0 = 2x speed")},
                  {"which", prop("string", "qpc|tick|tick64|all")} }, {"pid", "scale"}),
        [](const Json& a) {
            double sc = a.has("scale") ? a.at("scale").as_d() : 1.0;
            std::string w = a.has("which") ? a.at("which").as_s() : "qpc";
            return ok(speedhack((uint32_t)parse_u64(a.at("pid")), sc, w));
        });
}

} // namespace cmcp
