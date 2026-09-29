#include "cheatmcp.hpp"

#include <winternl.h>
#include <psapi.h>
#include <algorithm>
#include <cstdio>
#include <cstring>

#pragma comment(lib, "psapi.lib")

namespace cmcp {

// =============================================================================
// NtQuerySystemInformation plumbing for handle enumeration
// =============================================================================
typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);

#ifndef SystemExtendedHandleInformation
#define SystemExtendedHandleInformation 64
#endif
#ifndef SystemHandleInformation
#define SystemHandleInformation 16
#endif

struct HandleEntryEx {
    void*     Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG     GrantedAccess;
    USHORT    CreatorBackTraceIndex;
    USHORT    ObjectTypeIndex;
    ULONG     HandleAttributes;
    ULONG     Reserved;
};

struct HandleInfoEx {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    HandleEntryEx Handles[1];
};

struct HandleEntry32 {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR  ObjectTypeIndex;
    UCHAR  HandleAttributes;
    USHORT HandleValue;
    void*  Object;
    ULONG  GrantedAccess;
};

struct HandleInfo32 {
    ULONG_PTR NumberOfHandles;
    HandleEntry32 Handles[1];
};

struct FoundHandle {
    uint32_t from_pid;
    uint64_t handle;
    uint32_t access;
    void*    object;
};

// scalar target-os object for the process, derived from our own handle
static std::vector<FoundHandle> scan_handles(uint32_t pid, void*& target_object) {
    std::vector<FoundHandle> out;
    target_object = nullptr;

    HMODULE nt = GetModuleHandleA("ntdll.dll");
    if (!nt) return out;
    auto ntqsi = (pNtQuerySystemInformation)GetProcAddress(nt, "NtQuerySystemInformation");
    if (!ntqsi) return out;

    ULONG size = 1 << 20;
    std::vector<uint8_t> buf;
    NTSTATUS st = 0;
    for (int tries = 0; tries < 8; ++tries) {
        buf.resize(size);
        ULONG ret = 0;
        st = ntqsi(SystemExtendedHandleInformation, buf.data(), size, &ret);
        if (st == 0) break;
        size = ret + (1 << 16);
    }

    uint32_t our_pid = GetCurrentProcessId();
    HANDLE our_handle = (HANDLE)(uintptr_t)get_handle(pid);

    // First locate the kernel object pointer via our own handle to the target.
    auto info = (HandleInfoEx*)buf.data();
    if (st == 0 && info->NumberOfHandles < 10'000'000) {
        for (ULONG_PTR k = 0; k < info->NumberOfHandles; ++k) {
            auto& e = info->Handles[k];
            if (e.UniqueProcessId == our_pid && e.HandleValue == (ULONG_PTR)our_handle) {
                target_object = e.Object;
                break;
            }
        }
        if (target_object) {
            for (ULONG_PTR k = 0; k < info->NumberOfHandles; ++k) {
                auto& e = info->Handles[k];
                if (e.Object == target_object && e.UniqueProcessId != our_pid) {
                    out.push_back({ (uint32_t)e.UniqueProcessId, (uint64_t)e.HandleValue,
                                    (uint32_t)e.GrantedAccess, e.Object });
                }
            }
        }
    }
    return out;
}

// =============================================================================
// debug checks
// =============================================================================
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static Json query_proc(HANDLE h, ULONG cls, const char* label) {
    Json j = Json::obj();
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    auto fn = (pNtQueryInformationProcess)GetProcAddress(nt, "NtQueryInformationProcess");
    if (!fn) return j;
    ULONG_PTR val = 0;
    ULONG ret = 0;
    NTSTATUS st = fn(h, cls, &val, sizeof(val), &ret);
    j.set("class", (long long)cls);
    j.set("label", label);
    j.set("ntstatus", (long long)st);
    j.set("value", u64_hex((uint64_t)val));
    return j;
}

Json ac_check_debug(uint32_t pid) {
    Json r = Json::obj();
    r.set("self_debugger_present", IsDebuggerPresent() != FALSE);

    BOOL remote = FALSE;
    HANDLE h = get_handle(pid);
    if (h) CheckRemoteDebuggerPresent(h, &remote);
    r.set("remote_debugger_present", remote != FALSE);

    Json checks = Json::arr();
    if (h) {
        checks.push(query_proc(h, 7,    "ProcessDebugPort"));
        checks.push(query_proc(h, 0x1F, "ProcessDebugFlags"));
        checks.push(query_proc(h, 0x1E, "ProcessDebugObjectHandle"));
    }
    r.set("nt_queries", std::move(checks));
    return r;
}

// =============================================================================
// anti-cheat detection
// =============================================================================
static const char* kAcModules[] = {
    "easyanticheat", "easyanticheat_eos", "beservice", "beclient", "battleye",
    "vgk", "vgc", "vgtray", "mhyprot", "gameguard", "nprotect", "xigncode",
    "xhunter", "byfron", "hyperion", "denuvo", "vmprotect", "themida",
    "sguard", "ace-base", "ace-game", "tenprotect", "tp3helper",
    "punkbuster", "pnkbstra", "pnkbstrb", "fairfight", "arbiter", "battleye.exe",
    "robloxcrashhandler", "robloxplayerbeta",
};

static const char* kAcDrivers[] = {
    "vgk.sys", "easyanticheat.sys", "easyanticheat_eos.sys", "bedaisy.sys",
    "bedaisy64.sys", "mhyprot2.sys", "mhyprot3.sys", "ace-base.sys", "ace-game.sys",
    "sguard64.sys", "sguardsvc64.sys", "gedriver.sys", "npggnt.sys", "npptnt2.sys",
    "xhunter1.sys", "dtscsi.sys", "dtb.sys", "kslink.sys", "pnkbstrk.sys",
    "bprotect.sys", "vboxdrv.sys" /* hypervisor-ish */,
};

Json ac_kernel_drivers() {
    Json r = Json::obj();
    LPVOID drivers[1024];
    DWORD needed = 0;
    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &needed)) {
        r.set("error", "EnumDeviceDrivers failed (need admin)");
        return r;
    }
    DWORD n = needed / sizeof(LPVOID);
    Json list = Json::arr();
    Json hits = Json::arr();
    for (DWORD k = 0; k < n; ++k) {
        char name[MAX_PATH] = {};
        if (!GetDeviceDriverBaseNameA(drivers[k], name, sizeof(name) - 1)) continue;
        Json d = Json::obj();
        d.set("name", name);
        d.set("base", u64_hex((uint64_t)(uintptr_t)drivers[k]));
        list.push(d);
        std::string ln = lower(name);
        for (auto* ac : kAcDrivers) {
            if (ln == lower(ac)) { hits.push(std::string(name)); break; }
        }
    }
    r.set("count", (long long)n);
    r.set("matched_anticheat", std::move(hits));
    r.set("drivers", std::move(list));
    return r;
}

Json ac_detect(uint32_t pid) {
    Json r = Json::obj();
    r.set("pid", (long long)pid);

    Json matched = Json::arr();
    auto mods = list_modules(pid);
    for (auto& m : mods) {
        std::string n = lower(m.name);
        for (auto* ac : kAcModules) {
            if (n.find(ac) != std::string::npos) {
                Json e = Json::obj();
                e.set("module", m.name);
                e.set("base", u64_hex(m.base));
                e.set("signature", ac);
                matched.push(e);
                break;
            }
        }
    }
    r.set("user_mode_matches", std::move(matched));
    r.set("module_count", (long long)mods.size());

    Json drv = ac_kernel_drivers();
    r.set("kernel_matches", drv.has("matched_anticheat") ? drv.at("matched_anticheat") : Json::arr());

    HANDLE h = get_handle(pid);
    r.set("opened", h != nullptr);
    return r;
}

// =============================================================================
// handle enumeration / stripping
// =============================================================================
Json ac_list_handles(uint32_t pid) {
    Json r = Json::obj();
    void* obj = nullptr;
    auto found = scan_handles(pid, obj);
    r.set("target_pid", (long long)pid);
    r.set("target_object", obj ? u64_hex((uint64_t)(uintptr_t)obj) : std::string("unknown"));
    r.set("count", (long long)found.size());

    Json arr = Json::arr();
    for (auto& f : found) {
        Json e = Json::obj();
        e.set("from_pid", (long long)f.from_pid);
        e.set("handle", u64_hex(f.handle));
        e.set("access", u64_hex(f.access));
        arr.push(std::move(e));
    }
    r.set("handles", std::move(arr));
    return r;
}

size_t ac_close_handles(uint32_t pid) {
    void* obj = nullptr;
    auto found = scan_handles(pid, obj);
    size_t closed = 0;

    for (auto& f : found) {
        HANDLE src = OpenProcess(PROCESS_DUP_HANDLE, FALSE, f.from_pid);
        if (!src) continue;
        HANDLE dummy = nullptr;
        // DUPLICATE_CLOSE_SOURCE without a destination closes the source handle.
        BOOL ok = DuplicateHandle(src, (HANDLE)(uintptr_t)f.handle, nullptr, &dummy,
                                  0, FALSE, DUPLICATE_CLOSE_SOURCE);
        if (ok) ++closed;
        CloseHandle(src);
    }
    return closed;
}

} // namespace cmcp
