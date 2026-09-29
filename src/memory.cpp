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
// helpers
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
        else continue; // skip spaces, commas, 0x, etc.
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
// privileges
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

// -----------------------------------------------------------------------------
// process enumeration
// -----------------------------------------------------------------------------
std::vector<ProcInfo> list_processes() {
    std::vector<ProcInfo> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    // Process PPID field exists in PROCESSENTRY32 (th32ParentProcessID)
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
    for (auto& p : list_processes()) {
        if (lower(p.name) == want) return p;
    }
    // substring fallback
    for (auto& p : list_processes()) {
        if (lower(p.name).find(want) != std::string::npos) return p;
    }
    return std::nullopt;
}

// -----------------------------------------------------------------------------
// handle cache
// -----------------------------------------------------------------------------
static std::mutex g_handle_mtx;
static std::map<uint32_t, HANDLE> g_handles;

HANDLE get_handle(uint32_t pid) {
    std::lock_guard<std::mutex> lk(g_handle_mtx);
    auto it = g_handles.find(pid);
    if (it != g_handles.end()) return it->second;

    HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!h) h = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
        PROCESS_CREATE_THREAD | PROCESS_SUSPEND_RESUME,
        FALSE, pid);
    if (h) g_handles[pid] = h;
    return h;
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
        // fall back to 32-bit listing
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
bool read_mem(uint32_t pid, uint64_t addr, void* buf, size_t n) {
    HANDLE h = get_handle(pid);
    if (!h) return false;
    SIZE_T got = 0;
    return ReadProcessMemory(h, (LPCVOID)(uintptr_t)addr, buf, n, &got) && got == n;
}

bool write_mem(uint32_t pid, uint64_t addr, const void* buf, size_t n) {
    HANDLE h = get_handle(pid);
    if (!h) return false;

    SIZE_T done = 0;
    if (WriteProcessMemory(h, (LPVOID)(uintptr_t)addr, buf, n, &done) && done == n) return true;

    // retry after lifting page protection
    DWORD oldp = 0;
    if (VirtualProtectEx(h, (LPVOID)(uintptr_t)addr, n, PAGE_EXECUTE_READWRITE, &oldp)) {
        bool ok = WriteProcessMemory(h, (LPVOID)(uintptr_t)addr, buf, n, &done) && done == n;
        VirtualProtectEx(h, (LPVOID)(uintptr_t)addr, n, oldp, &oldp);
        return ok;
    }
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
