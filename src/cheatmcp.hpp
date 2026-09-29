// cheat-mcp — public interface for the whole server.
#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <atomic>
#include <thread>
#include <optional>
#include <functional>

#include "json.hpp"

namespace cmcp {

// ============================================================ process / modules
struct ProcInfo {
    uint32_t pid = 0;
    uint32_t ppid = 0;
    std::string name;
    std::string path;
    bool wow64 = false;
};

struct ModInfo {
    std::string name;
    std::string path;
    uint64_t base = 0;
    uint64_t size = 0;
};

bool enable_debug_privilege();

std::vector<ProcInfo> list_processes();
std::vector<ModInfo>  list_modules(uint32_t pid);
std::vector<ProcInfo> list_threads_owners();                 // (unused helper kept simple)
std::vector<std::pair<uint32_t, std::string>> list_threads(uint32_t pid);

std::optional<ModInfo>  find_module(uint32_t pid, const std::string& name);
std::optional<ProcInfo> find_process(const std::string& name);

HANDLE get_handle(uint32_t pid);
void   drop_handle(uint32_t pid);
bool   is_process_64(uint32_t pid);

// ============================================================ memory
bool read_mem(uint32_t pid, uint64_t addr, void* buf, size_t n);
bool write_mem(uint32_t pid, uint64_t addr, const void* buf, size_t n);
uint64_t alloc_mem(uint32_t pid, size_t n, uint32_t protect);
bool free_mem(uint32_t pid, uint64_t addr);
bool protect_mem(uint32_t pid, uint64_t addr, size_t n, uint32_t newprot, uint32_t* oldprot = nullptr);
std::vector<MEMORY_BASIC_INFORMATION> query_regions(uint32_t pid, uint64_t start = 0, uint64_t end = ~0ull);

// ============================================================ scanner
enum class ScanType { I8, I16, I32, I64, F32, F64, Str, Aob };

struct ScanHit {
    uint64_t addr = 0;
    std::vector<uint8_t> prev;
};

struct ScanState {
    bool active = false;
    ScanType type = ScanType::I32;
    size_t width = 4;
    std::string pattern;
    std::vector<ScanHit> hits;
    std::mutex mtx;
};

ScanState& scan_state();

size_t scan_first(uint32_t pid, ScanType type, const std::string& value, bool writable_only, size_t max_hits);
size_t scan_aob(uint32_t pid, const std::string& pattern, bool writable_only, size_t max_hits);
size_t scan_refine(uint32_t pid, const std::string& mode, const std::string& value);
Json   scan_results(size_t offset, size_t limit, uint32_t pid, const std::string& type_name);
Json   pointer_scan(uint32_t pid, uint64_t target, size_t max_offset, size_t max_results);
void   scan_reset();

// ============================================================ injection
struct InjectResult {
    bool ok = false;
    uint64_t value = 0;
    std::string error;
};

InjectResult inject_dll(uint32_t pid, const std::string& dll, const std::string& method);
InjectResult inject_shellcode(uint32_t pid, const std::vector<uint8_t>& code);
bool eject_dll(uint32_t pid, uint64_t base, std::string& err);
InjectResult run_remote(uint32_t pid, uint64_t fn, uint64_t arg);

// ============================================================ anticheat
Json   ac_detect(uint32_t pid);
Json   ac_list_handles(uint32_t pid);
Json   ac_check_debug(uint32_t pid);
Json   ac_kernel_drivers();
size_t ac_close_handles(uint32_t pid);

// ============================================================ network
Json net_connections(int pid_filter);
Json net_resolve(const std::string& host);
bool net_send_udp(const std::string& host, uint16_t port, const std::vector<uint8_t>& data, std::string& err);
bool net_send_tcp(const std::string& host, uint16_t port, const std::vector<uint8_t>& data, std::string& err);
Json net_capture(const std::string& filter_ip, int max_packets, int timeout_ms);
Json net_send_raw_ip(uint32_t dst_ip_be, const std::vector<uint8_t>& ip_packet);

// ============================================================ runtime features
Json freeze_add(uint32_t pid, uint64_t addr, const std::vector<uint8_t>& data);
Json freeze_remove(int id);
Json freeze_list();

Json watch_add(uint32_t pid, uint64_t addr, size_t width, const std::string& type);
Json watch_poll(int id);
Json watch_remove(int id);

Json iat_hook(uint32_t pid, const std::string& module, const std::string& import,
              const std::vector<uint8_t>& stub);
Json speedhack(uint32_t pid, double scale, const std::string& which);

void runtime_start();
void runtime_stop();

// ============================================================ tool registry / mcp
struct ToolResult {
    bool is_error = false;
    std::string text;
    Json structured;
};

using ToolFn = std::function<ToolResult(const Json&)>;

struct Tool {
    std::string name;
    std::string description;
    Json schema;
    ToolFn fn;
};

class Registry {
public:
    void add(const std::string& name, const std::string& desc, Json schema, ToolFn fn);
    const std::map<std::string, Tool>& all() const { return tools_; }
    ToolResult call(const std::string& name, const Json& args) const;
private:
    std::map<std::string, Tool> tools_;
};

Registry& registry();
void register_all_tools();

int run_server();

// ============================================================ helpers
std::vector<uint8_t> parse_hex(const std::string& s);
std::string to_hex(const uint8_t* p, size_t n);
std::string basename(const std::string& p);
std::string lower(std::string s);
uint64_t parse_u64(const Json& j);
std::string u64_hex(uint64_t v);

} // namespace cmcp
