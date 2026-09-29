#include "cheatmcp.hpp"

#include <winternl.h>
#include <tlhelp32.h>
#include <fstream>
#include <cstring>
#include <cstdio>
#include <vector>
#include <string>

namespace cmcp {

// =============================================================================
// generic helpers
// =============================================================================
static uint64_t remote_fn_from_our_offset(uint32_t pid, const char* module_name,
                                          uint64_t our_fn) {
    HMODULE our_mod = GetModuleHandleA(module_name);
    if (!our_mod) return 0;
    uint64_t offset = our_fn - (uint64_t)(uintptr_t)our_mod;

    auto tm = find_module(pid, module_name);
    if (!tm) return 0;
    return tm->base + offset;
}

static std::vector<uint8_t> read_file_bytes(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)),
                                 std::istreambuf_iterator<char>());
}

// =============================================================================
// remote thread creation (x64 / x86)
// =============================================================================
typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, LPVOID ObjectAttributes,
    HANDLE ProcessHandle, LPVOID StartRoutine, LPVOID Argument, ULONG CreateFlags,
    SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, LPVOID AttributeList);

static HANDLE create_remote_thread_nt(HANDLE proc, uint64_t start, uint64_t arg) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return nullptr;
    auto fn = (pNtCreateThreadEx)GetProcAddress(ntdll, "NtCreateThreadEx");
    if (!fn) return nullptr;

    HANDLE th = nullptr;
    NTSTATUS st = fn(&th, THREAD_ALL_ACCESS, nullptr, proc,
                     (LPVOID)(uintptr_t)start, (LPVOID)(uintptr_t)arg,
                     0, 0, 0, 0, nullptr);
    if (st < 0) return nullptr;
    return th;
}

// =============================================================================
// LoadLibrary-style injection via several launch mechanisms
// =============================================================================
static InjectResult remote_loadlibrary(uint32_t pid, const std::string& dll,
                                       const std::string& method) {
    InjectResult res;
    HANDLE proc = get_handle(pid);
    if (!proc) { res.error = "cannot open process"; return res; }

    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    if (!k32) { res.error = "no kernel32 in our process"; return res; }

    uint64_t loadlib = remote_fn_from_our_offset(pid, "kernel32.dll",
                         (uint64_t)(uintptr_t)GetProcAddress(k32, "LoadLibraryA"));
    if (!loadlib) { res.error = "cannot locate kernel32!LoadLibraryA in target"; return res; }

    size_t len = dll.size() + 1;
    uint64_t remote_str = alloc_mem(pid, len, PAGE_READWRITE);
    if (!remote_str) { res.error = "VirtualAllocEx failed"; return res; }
    if (!write_mem(pid, remote_str, dll.c_str(), len)) {
        res.error = "WriteProcessMemory(path) failed";
        free_mem(pid, remote_str);
        return res;
    }

    std::string m = lower(method);

    if (m == "loadlibrary" || m == "") {
        HANDLE th = CreateRemoteThread(proc, nullptr, 0,
                        (LPTHREAD_START_ROUTINE)(uintptr_t)loadlib,
                        (LPVOID)(uintptr_t)remote_str, 0, nullptr);
        if (!th) { res.error = "CreateRemoteThread failed: " + std::to_string(GetLastError()); return res; }
        WaitForSingleObject(th, 8000);
        DWORD code = 0;
        GetExitCodeThread(th, &code);
        CloseHandle(th);
        res.ok = code != 0;
        res.value = code;
        if (!res.ok) res.error = "LoadLibrary returned NULL";
    } else if (m == "nt" || m == "ntcreatethreadex") {
        HANDLE th = create_remote_thread_nt(proc, loadlib, remote_str);
        if (!th) { res.error = "NtCreateThreadEx failed"; return res; }
        WaitForSingleObject(th, 8000);
        DWORD code = 0;
        GetExitCodeThread(th, &code);
        CloseHandle(th);
        res.ok = code != 0;
        res.value = code;
    } else if (m == "hijack" || m == "threadhijack") {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) { res.error = "thread snapshot failed"; return res; }
        THREADENTRY32 te{}; te.dwSize = sizeof(te);
        bool done = false;
        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID != pid) continue;
                HANDLE th = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                if (!th) continue;
                SuspendThread(th);
                CONTEXT ctx{};
                ctx.ContextFlags = CONTEXT_FULL;
#ifdef _WIN64
                if (GetThreadContext(th, &ctx)) {
                    ctx.Rip = loadlib;
                    ctx.Rcx = remote_str;
                    SetThreadContext(th, &ctx);
                    done = true;
                }
#else
                if (GetThreadContext(th, &ctx)) {
                    ctx.Eip = (DWORD)loadlib;
                    DWORD sp = ctx.Esp;
                    DWORD arg = (DWORD)remote_str;
                    WriteProcessMemory(proc, (LPVOID)(uintptr_t)(sp - 4), &arg, 4, nullptr);
                    ctx.Esp = sp - 4;
                    SetThreadContext(th, &ctx);
                    done = true;
                }
#endif
                ResumeThread(th);
                CloseHandle(th);
                if (done) break;
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
        res.ok = done;
        res.value = loadlib;
        if (!done) res.error = "no hijackable thread found";
    } else if (m == "apc") {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) { res.error = "thread snapshot failed"; return res; }
        THREADENTRY32 te{}; te.dwSize = sizeof(te);
        int queued = 0;
        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID != pid) continue;
                HANDLE th = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
                if (!th) continue;
                if (QueueUserAPC((PAPCFUNC)(uintptr_t)loadlib, th, (ULONG_PTR)remote_str)) ++queued;
                CloseHandle(th);
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
        res.ok = queued > 0;
        res.value = loadlib;
        if (!res.ok) res.error = "no thread accepted the APC (needs alertable wait)";
    } else if (m == "wndhook" || m == "sethook") {
        HMODULE local = LoadLibraryA(dll.c_str());
        if (!local) { res.error = "LoadLibrary locally failed"; return res; }
        auto tids = list_threads(pid);
        if (tids.empty()) { res.error = "no threads"; return res; }
        // A generic export name is required by the caller's DLL; default "HookProc"
        FARPROC proc_addr = GetProcAddress(local, "HookProc");
        HHOOK hk = SetWindowsHookExA(WH_CBT, (HOOKPROC)proc_addr, local, tids[0].first);
        res.ok = hk != nullptr;
        res.value = (uint64_t)(uintptr_t)hk;
        if (!res.ok) res.error = "SetWindowsHookEx failed (needs HookProc export)";
    } else {
        res.error = "unknown method: " + method;
    }

    return res;
}

// =============================================================================
// manual map
// =============================================================================
static uint64_t target_base_for(uint32_t pid, const std::string& dll_name) {
    auto m = find_module(pid, dll_name);
    return m ? m->base : 0;
}

InjectResult manual_map(uint32_t pid, const std::string& dllpath) {
    InjectResult res;

    std::vector<uint8_t> file = read_file_bytes(dllpath);
    if (file.size() < sizeof(IMAGE_DOS_HEADER)) { res.error = "cannot read file"; return res; }

    auto dos = (IMAGE_DOS_HEADER*)file.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { res.error = "bad MZ"; return res; }
    auto nt = (IMAGE_NT_HEADERS*)(file.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { res.error = "bad PE"; return res; }

    uint64_t preferred = nt->OptionalHeader.ImageBase;
    size_t image_size = nt->OptionalHeader.SizeOfImage;
    auto sections = IMAGE_FIRST_SECTION(nt);
    uint16_t nsec = nt->FileHeader.NumberOfSections;
    bool is64 = nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;

    HANDLE proc = get_handle(pid);
    if (!proc) { res.error = "cannot open process"; return res; }

    // writable scratch image
    std::vector<uint8_t> img(image_size, 0);
    std::memcpy(img.data(), file.data(), nt->OptionalHeader.SizeOfHeaders);
    for (uint16_t s = 0; s < nsec; ++s) {
        auto& sec = sections[s];
        if (sec.SizeOfRawData == 0) continue;
        size_t dst = sec.VirtualAddress;
        size_t src = sec.PointerToRawData;
        if (dst + sec.SizeOfRawData > image_size) continue;
        if (src + sec.SizeOfRawData > file.size()) continue;
        std::memcpy(img.data() + dst, file.data() + src, sec.SizeOfRawData);
    }

    // allocate in target (prefer the original base)
    uint64_t remote = (uint64_t)(uintptr_t)VirtualAllocEx(
        proc, (LPVOID)(uintptr_t)preferred, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote)
        remote = (uint64_t)(uintptr_t)VirtualAllocEx(
            proc, nullptr, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote) { res.error = "VirtualAllocEx failed"; return res; }

    int64_t delta = (int64_t)remote - (int64_t)preferred;

    // relocations
    auto& reloc_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (delta != 0 && reloc_dir.Size) {
        auto block = (IMAGE_BASE_RELOCATION*)(img.data() + reloc_dir.VirtualAddress);
        while ((uint8_t*)block < img.data() + reloc_dir.VirtualAddress + reloc_dir.Size &&
               block->SizeOfBlock > 0) {
            DWORD n = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* items = (WORD*)(block + 1);
            for (DWORD k = 0; k < n; ++k) {
                WORD type = items[k] >> 12;
                WORD off  = items[k] & 0x0FFF;
                uint8_t* patch = img.data() + block->VirtualAddress + off;
                if (patch < img.data() || patch >= img.data() + image_size) continue;
                if (type == IMAGE_REL_BASED_DIR64 && is64) {
                    *(uint64_t*)patch += (uint64_t)delta;
                } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                    *(uint32_t*)patch += (uint32_t)delta;
                } else if (type == IMAGE_REL_BASED_ABSOLUTE) {
                    // padding, ignore
                }
            }
            block = (IMAGE_BASE_RELOCATION*)((uint8_t*)block + block->SizeOfBlock);
        }
    }

    // imports
    auto& imp_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (imp_dir.Size) {
        auto imp = (IMAGE_IMPORT_DESCRIPTOR*)(img.data() + imp_dir.VirtualAddress);
        for (; imp->Name; ++imp) {
            const char* dll_name = (const char*)(img.data() + imp->Name);
            uint64_t tbase = target_base_for(pid, dll_name);
            if (!tbase) continue; // module not loaded in target; leave for runtime

            HMODULE our_mod = LoadLibraryA(dll_name);
            if (!our_mod) continue;
            uint64_t our_base = (uint64_t)(uintptr_t)our_mod;

            auto thunk = (IMAGE_THUNK_DATA*)(img.data() + imp->FirstThunk);
            auto orig  = (IMAGE_THUNK_DATA*)(img.data() + (imp->OriginalFirstThunk
                                                          ? imp->OriginalFirstThunk
                                                          : imp->FirstThunk));
            for (; orig->u1.AddressOfData; ++orig, ++thunk) {
                uint64_t fn_addr = 0;
                if (IMAGE_SNAP_BY_ORDINAL(orig->u1.Ordinal)) {
                    fn_addr = (uint64_t)(uintptr_t)GetProcAddress(our_mod,
                                  (LPCSTR)(uintptr_t)IMAGE_ORDINAL(orig->u1.Ordinal));
                } else {
                    auto ibn = (IMAGE_IMPORT_BY_NAME*)(img.data() + orig->u1.AddressOfData);
                    fn_addr = (uint64_t)(uintptr_t)GetProcAddress(our_mod, (LPCSTR)ibn->Name);
                }
                if (fn_addr) {
                    uint64_t tfn = tbase + (fn_addr - our_base);
                    thunk->u1.Function = tfn;
                }
            }
        }
    }

    // write the mapped image
    if (!write_mem(pid, remote, img.data(), image_size)) {
        res.error = "WriteProcessMemory(image) failed";
        free_mem(pid, remote);
        return res;
    }

    // per-section protections
    for (uint16_t s = 0; s < nsec; ++s) {
        auto& sec = sections[s];
        DWORD ch = sec.Characteristics;
        DWORD prot = PAGE_READONLY;
        if (ch & IMAGE_SCN_MEM_EXECUTE) prot = (ch & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        else if (ch & IMAGE_SCN_MEM_WRITE) prot = PAGE_READWRITE;
        if (sec.Misc.VirtualSize)
            protect_mem(pid, remote + sec.VirtualAddress, sec.Misc.VirtualSize, prot);
    }

    // DllMain stub
    uint64_t entry = remote + nt->OptionalHeader.AddressOfEntryPoint;
    std::vector<uint8_t> stub;
    if (is64) {
        auto push64 = [&](std::vector<uint8_t>& v, uint64_t x) {
            for (int k = 0; k < 8; ++k) v.push_back((uint8_t)((x >> (8 * k)) & 0xFF));
        };
        stub.push_back(0x48); stub.push_back(0xB9); push64(stub, remote);      // mov rcx, base
        stub.insert(stub.end(), {0x48,0xC7,0xC2,0x01,0x00,0x00,0x00});         // mov rdx, 1
        stub.insert(stub.end(), {0x4D,0x31,0xC0});                             // xor r8, r8
        stub.push_back(0x48); stub.push_back(0xB8); push64(stub, entry);       // mov rax, entry
        stub.insert(stub.end(), {0xFF,0xD0,0xC3});                             // call rax; ret
    } else {
        auto push32 = [&](std::vector<uint8_t>& v, uint32_t x) {
            for (int k = 0; k < 4; ++k) v.push_back((uint8_t)((x >> (8 * k)) & 0xFF));
        };
        stub.insert(stub.end(), {0x6A,0x00,0x6A,0x01});                        // push 0; push 1
        stub.push_back(0x68); push32(stub, (uint32_t)remote);                  // push base
        stub.push_back(0xB8); push32(stub, (uint32_t)entry);                   // mov eax, entry
        stub.insert(stub.end(), {0xFF,0xD0,0xC3});                             // call eax; ret
    }

    uint64_t stub_addr = alloc_mem(pid, stub.size(), PAGE_EXECUTE_READWRITE);
    if (!stub_addr) { res.error = "stub alloc failed"; return res; }
    if (!write_mem(pid, stub_addr, stub.data(), stub.size())) {
        res.error = "stub write failed";
        return res;
    }

    HANDLE th = CreateRemoteThread(proc, nullptr, 0,
                    (LPTHREAD_START_ROUTINE)(uintptr_t)stub_addr,
                    nullptr, 0, nullptr);
    if (th) { WaitForSingleObject(th, 8000); CloseHandle(th); }

    res.ok = true;
    res.value = remote;
    return res;
}

// =============================================================================
// public API
// =============================================================================
InjectResult inject_dll(uint32_t pid, const std::string& dll, const std::string& method) {
    std::string m = lower(method);
    if (m == "manualmap" || m == "manual" || m == "map")
        return manual_map(pid, dll);
    return remote_loadlibrary(pid, dll, method);
}

InjectResult inject_shellcode(uint32_t pid, const std::vector<uint8_t>& code) {
    InjectResult res;
    if (code.empty()) { res.error = "empty shellcode"; return res; }
    HANDLE proc = get_handle(pid);
    if (!proc) { res.error = "cannot open process"; return res; }

    uint64_t mem = alloc_mem(pid, code.size(), PAGE_EXECUTE_READWRITE);
    if (!mem) { res.error = "alloc failed"; return res; }
    if (!write_mem(pid, mem, code.data(), code.size())) { res.error = "write failed"; return res; }

    HANDLE th = create_remote_thread_nt(proc, mem, 0);
    if (!th) th = CreateRemoteThread(proc, nullptr, 0,
                       (LPTHREAD_START_ROUTINE)(uintptr_t)mem, nullptr, 0, nullptr);
    if (!th) { res.error = "CreateRemoteThread failed"; return res; }

    res.ok = true;
    res.value = mem;
    CloseHandle(th);
    return res;
}

bool eject_dll(uint32_t pid, uint64_t base, std::string& err) {
    HANDLE proc = get_handle(pid);
    if (!proc) { err = "cannot open process"; return false; }

    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    uint64_t freelib = remote_fn_from_our_offset(pid, "kernel32.dll",
                        (uint64_t)(uintptr_t)GetProcAddress(k32, "FreeLibrary"));
    if (!freelib) { err = "cannot locate FreeLibrary"; return false; }

    HANDLE th = CreateRemoteThread(proc, nullptr, 0,
                    (LPTHREAD_START_ROUTINE)(uintptr_t)freelib,
                    (LPVOID)(uintptr_t)base, 0, nullptr);
    if (!th) { err = "CreateRemoteThread failed"; return false; }
    WaitForSingleObject(th, 5000);
    CloseHandle(th);
    return true;
}

InjectResult run_remote(uint32_t pid, uint64_t fn, uint64_t arg) {
    InjectResult res;
    HANDLE proc = get_handle(pid);
    if (!proc) { res.error = "cannot open process"; return res; }
    HANDLE th = create_remote_thread_nt(proc, fn, arg);
    if (!th) th = CreateRemoteThread(proc, nullptr, 0,
                       (LPTHREAD_START_ROUTINE)(uintptr_t)fn,
                       (LPVOID)(uintptr_t)arg, 0, nullptr);
    if (!th) { res.error = "thread creation failed"; return res; }
    WaitForSingleObject(th, 8000);
    DWORD code = 0;
    GetExitCodeThread(th, &code);
    CloseHandle(th);
    res.ok = true;
    res.value = code;
    return res;
}

} // namespace cmcp
