#include "cheatmcp.hpp"

#include <psapi.h>
#include <tlhelp32.h>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>

#pragma comment(lib, "psapi.lib")

namespace cmcp {

// -----------------------------------------------------------------------------
// string helpers
// -----------------------------------------------------------------------------
std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    return s;
}

std::string basename(const std::string& p) {
    size_t s = p.find_last_of("\\/");
    return s == std::string::npos ? p : p.substr(s + 1);
}

std::string u64_hex(uint64_t v) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "0x%llX", (unsigned long long)v);
    return buf;
}

uint64_t parse_u64(const Json& j) {
    if (j.is_num()) return (uint64_t)j.as_i();
    if (j.is_str()) {
        const std::string& s = j.s;
        try {
            if (s.rfind("0x", 0) == 0 || s.rfind("0X", 0) == 0)
                return std::stoull(s.substr(2), nullptr, 16);
            return std::stoull(s, nullptr, 0);
        } catch (...) { return 0; }
    }
    return 0;
}

std::vector<uint8_t> parse_hex(const std::string& s) {
    std::vector<uint8_t> out;
    int hi = -1;
    for (char c : s) {
        int v;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else continue;
        if (hi < 0) hi = v;
        else { out.push_back((uint8_t)((hi << 4) | v)); hi = -1; }
    }
    return out;
}

std::string to_hex(const uint8_t* p, size_t n) {
    static const char* d = "0123456789ABCDEF";
    std::string out;
    out.reserve(n * 3);
    for (size_t k = 0; k < n; ++k) {
        if (k) out.push_back(' ');
        out.push_back(d[p[k] >> 4]);
        out.push_back(d[p[k] & 15]);
    }
    return out;
}

// -----------------------------------------------------------------------------
// win32 error reporting
// -----------------------------------------------------------------------------
std::string win32_error_string(DWORD err) {
    LPSTR buf = nullptr;
    DWORD n = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&buf, 0, nullptr);
    std::string s;
    if (n && buf) {
        s.assign(buf, n);
        while (!s.empty() && (s.back() == '\r' || s.back() == '\n' || s.back() == ' ')) s.pop_back();
        LocalFree(buf);
    } else {
        s = "unknown error";
    }
    return s;
}

std::string win32_hint(DWORD err) {
    switch (err) {
        case ERROR_ACCESS_DENIED:
            return "ACCESS_DENIED (target protected, PPL, UIPI, or not elevated) — try elevate()";
        case ERROR_INVALID_PARAMETER:
            return "INVALID_PARAMETER (bad address/size/protection)";
        case ERROR_INVALID_HANDLE:
            return "INVALID_HANDLE (process handle closed or never opened)";
        case ERROR_PARTIAL_COPY:
            return "PARTIAL_COPY (part of the range is unmapped/unreadable — read page-aligned or smaller)";
        case ERROR_NOACCESS:
            return "NOACCESS (page not readable; check memory_regions)";
        case ERROR_FILE_NOT_FOUND:
            return "FILE_NOT_FOUND (process/module/path not found)";
        case ERROR_ELEVATION_REQUIRED:
            return "ELEVATION_REQUIRED (operation needs admin — call elevate())";
        case ERROR_NOT_ALL_ASSIGNED:
            return "NOT_ALL_ASSIGNED (privilege could not be enabled; token not elevated)";
        case ERROR_ALREADY_EXISTS:
            return "ALREADY_EXISTS";
        case ERROR_NOT_FOUND:
            return "NOT_FOUND";
        default:
            return "";
    }
}

Json win32_error_json(DWORD err, const std::string& context) {
    Json j = Json::obj();
    j.set("context", context);
    j.set("win32_error", (long long)err);
    j.set("win32_message", win32_error_string(err));
    std::string h = win32_hint(err);
    if (!h.empty()) j.set("hint", h);
    return j;
}

// -----------------------------------------------------------------------------
// privileges / elevation
// -----------------------------------------------------------------------------
bool enable_debug_privilege() {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
        return false;
    LUID luid{};
    if (!LookupPrivilegeValueA(nullptr, SE_DEBUG_NAME, &luid)) { CloseHandle(tok); return false; }
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ok = AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    DWORD err = GetLastError();
    CloseHandle(tok);
    return ok && err == ERROR_SUCCESS;
}

bool current_process_elevated() {
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

// -----------------------------------------------------------------------------
// process enumeration
// -----------------------------------------------------------------------------
std::vector<ProcInfo> list_processes() {
    std::vector<ProcInfo> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            ProcInfo pi;
            pi.pid = pe.th32ProcessID;
            pi.ppid = pe.th32ParentProcessID;

            char narrow[MAX_PATH] = {};
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, narrow, sizeof(narrow) - 1, nullptr, nullptr);
            pi.name = narrow;

            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pi.pid);
            if (h) {
                char path[MAX_PATH * 2] = {};
                DWORD sz = sizeof(path) - 1;
                if (QueryFullProcessImageNameA(h, 0, path, &sz)) pi.path = path;
                BOOL isWow = FALSE;
                if (IsWow64Process(h, &isWow)) pi.wow64 = isWow != FALSE;
                CloseHandle(h);
            }
            out.push_back(std::move(pi));
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return out;
}

std::vector<ProcInfo> list_threads_owners() { return {}; }

std::vector<std::pair<uint32_t, std::string>> list_threads(uint32_t pid) {
    std::vector<std::pair<uint32_t, std::string>> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (pid == 0 || te.th32OwnerProcessID == pid)
                out.emplace_back(te.th32ThreadID, "");
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return out;
}

std::optional<ProcInfo> find_process(const std::string& name) {
    std::string want = lower(name);
    for (auto& p : list_processes()) if (lower(p.name) == want) return p;
    for (auto& p : list_processes()) if (lower(p.name).find(want) != std::string::npos) return p;
    return std::nullopt;
}

static uint64_t working_set_of(uint32_t pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return 0;
    PROCESS_MEMORY_COUNTERS pmc{};
    uint64_t ws = 0;
    if (GetProcessMemoryInfo(h, &pmc, sizeof(pmc))) ws = pmc.WorkingSetSize;
    CloseHandle(h);
    return ws;
}

std::vector<ProcCandidate> find_process_candidates(const std::string& name) {
    std::string want = lower(basename(name));
    std::vector<ProcCandidate> exact, partial;
    for (auto& p : list_processes()) {
        std::string n = lower(p.name);
        if (n == want) exact.push_back({ p, working_set_of(p.pid) });
        else if (n.find(want) != std::string::npos) partial.push_back({ p, working_set_of(p.pid) });
    }
    auto& use = exact.empty() ? partial : exact;
    std::sort(use.begin(), use.end(),
              [](const ProcCandidate& a, const ProcCandidate& b) {
                  return a.working_set > b.working_set;
              });
    return use;
}

// -----------------------------------------------------------------------------
// handle cache
// -----------------------------------------------------------------------------
static std::mutex g_handle_mtx;
static std::map<uint32_t, HANDLE> g_handles;

HANDLE get_handle_err(uint32_t pid, DWORD* err) {
    std::lock_guard<std::mutex> lk(g_handle_mtx);
    auto it = g_handles.find(pid);
    if (it != g_handles.end()) { if (err) *err = 0; return it->second; }

    HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    DWORD e1 = GetLastError();
    if (!h) {
        h = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
            PROCESS_CREATE_THREAD | PROCESS_SUSPEND_RESUME,
            FALSE, pid);
        e1 = GetLastError();
    }
    if (h) g_handles[pid] = h;
    if (err) *err = h ? 0 : e1;
    return h;
}

HANDLE get_handle(uint32_t pid) {
    return get_handle_err(pid, nullptr);
}

void drop_handle(uint32_t pid) {
    std::lock_guard<std::mutex> lk(g_handle_mtx);
    auto it = g_handles.find(pid);
    if (it != g_handles.end()) {
        CloseHandle(it->second);
        g_handles.erase(it);
    }
}

bool is_process_64(uint32_t pid) {
    HANDLE h = get_handle(pid);
    if (!h) return false;
    BOOL meWow = FALSE, targetWow = FALSE;
    IsWow64Process(GetCurrentProcess(), &meWow);
    IsWow64Process(h, &targetWow);
    return meWow ? false : (targetWow ? false : true);
}

// -----------------------------------------------------------------------------
// modules
// -----------------------------------------------------------------------------
std::vector<ModInfo> list_modules(uint32_t pid) {
    std::vector<ModInfo> out;
    HANDLE h = get_handle(pid);
    if (!h) return out;

    HMODULE mods[1024];
    DWORD needed = 0;
    if (!EnumProcessModulesEx(h, mods, sizeof(mods), &needed, LIST_MODULES_ALL)) {
        if (!EnumProcessModules(h, mods, sizeof(mods), &needed)) return out;
    }
    DWORD count = needed / sizeof(HMODULE);
    if (count > 1024) count = 1024;

    for (DWORD k = 0; k < count; ++k) {
        ModInfo mi;
        char name[MAX_PATH] = {};
        if (GetModuleBaseNameA(h, mods[k], name, sizeof(name) - 1)) mi.name = name;
        char path[MAX_PATH * 2] = {};
        if (GetModuleFileNameExA(h, mods[k], path, sizeof(path) - 1)) mi.path = path;

        MODULEINFO info{};
        if (GetModuleInformation(h, mods[k], &info, sizeof(info))) {
            mi.base = (uint64_t)(uintptr_t)info.lpBaseOfDll;
            mi.size = info.SizeOfImage;
        } else {
            mi.base = (uint64_t)(uintptr_t)mods[k];
        }
        out.push_back(std::move(mi));
    }
    return out;
}

std::optional<ModInfo> find_module(uint32_t pid, const std::string& name) {
    std::string want = lower(basename(name));
    auto mods = list_modules(pid);
    for (auto& m : mods) if (lower(m.name) == want) return m;
    for (auto& m : mods) if (lower(m.name).find(want) != std::string::npos) return m;
    return std::nullopt;
}

// -----------------------------------------------------------------------------
// memory primitives
// -----------------------------------------------------------------------------
bool read_mem(uint32_t pid, uint64_t addr, void* buf, size_t n, DWORD* err) {
    DWORD e = 0;
    HANDLE h = get_handle_err(pid, &e);
    if (!h) { if (err) *err = e; return false; }
    SIZE_T got = 0;
    BOOL ok = ReadProcessMemory(h, (LPCVOID)(uintptr_t)addr, buf, n, &got);
    if (!ok) { if (err) *err = GetLastError(); return false; }
    if (got != n) { if (err) *err = ERROR_PARTIAL_COPY; return false; }
    if (err) *err = 0;
    return true;
}

bool write_mem(uint32_t pid, uint64_t addr, const void* buf, size_t n, DWORD* err) {
    DWORD e = 0;
    HANDLE h = get_handle_err(pid, &e);
    if (!h) { if (err) *err = e; return false; }

    SIZE_T done = 0;
    if (WriteProcessMemory(h, (LPVOID)(uintptr_t)addr, buf, n, &done) && done == n) {
        if (err) *err = 0;
        return true;
    }
    DWORD werr = GetLastError();

    DWORD oldp = 0;
    if (VirtualProtectEx(h, (LPVOID)(uintptr_t)addr, n, PAGE_EXECUTE_READWRITE, &oldp)) {
        bool ok = WriteProcessMemory(h, (LPVOID)(uintptr_t)addr, buf, n, &done) && done == n;
        DWORD werr2 = ok ? 0 : GetLastError();
        VirtualProtectEx(h, (LPVOID)(uintptr_t)addr, n, oldp, &oldp);
        if (err) *err = werr2;
        return ok;
    }
    if (err) *err = werr;
    return false;
}

uint64_t alloc_mem(uint32_t pid, size_t n, uint32_t protect) {
    HANDLE h = get_handle(pid);
    if (!h) return 0;
    LPVOID p = VirtualAllocEx(h, nullptr, n, MEM_COMMIT | MEM_RESERVE, protect);
    return (uint64_t)(uintptr_t)p;
}

bool free_mem(uint32_t pid, uint64_t addr) {
    HANDLE h = get_handle(pid);
    if (!h) return false;
    return VirtualFreeEx(h, (LPVOID)(uintptr_t)addr, 0, MEM_RELEASE) != FALSE;
}

bool protect_mem(uint32_t pid, uint64_t addr, size_t n, uint32_t newprot, uint32_t* oldprot) {
    HANDLE h = get_handle(pid);
    if (!h) return false;
    DWORD oldp = 0;
    BOOL ok = VirtualProtectEx(h, (LPVOID)(uintptr_t)addr, n, newprot, &oldp);
    if (oldprot) *oldprot = oldp;
    return ok != FALSE;
}

std::vector<MEMORY_BASIC_INFORMATION> query_regions(uint32_t pid, uint64_t start, uint64_t end) {
    std::vector<MEMORY_BASIC_INFORMATION> out;
    HANDLE h = get_handle(pid);
    if (!h) return out;

    uint64_t addr = start;
    MEMORY_BASIC_INFORMATION mbi{};
    while (addr < end &&
           VirtualQueryEx(h, (LPCVOID)(uintptr_t)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        out.push_back(mbi);
        uint64_t next = (uint64_t)(uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
    }
    return out;
}

} // namespace cmcp
