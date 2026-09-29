// Elevated companion agent over a named pipe.
//
// Direction matters for UAC integrity levels: a medium-IL process may NOT write
// to a pipe owned by a high-IL process (no-write-up). So the unelevated parent
// creates the pipe SERVER, and the elevated agent connects as a CLIENT
// (writing downward is allowed). The pipe gets a permissive DACL so the
// elevated client can attach regardless of token.
#include "cheatmcp.hpp"

#include <shellapi.h>
#include <sddl.h>
#include <string>
#include <mutex>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")

namespace cmcp {

static HANDLE g_pipe = INVALID_HANDLE_VALUE;
static HANDLE g_proc = nullptr;
static std::string g_readbuf;
static std::mutex g_agent_mtx;
static std::atomic<bool> g_route{false};

bool elevated_route_enabled() { return g_route.load(); }
void set_elevated_route(bool v) { g_route.store(v); }

bool agent_connected() { return g_pipe != INVALID_HANDLE_VALUE; }

bool agent_alive() {
    if (!g_proc) return false;
    return WaitForSingleObject(g_proc, 0) == WAIT_TIMEOUT;
}

static std::string exe_path() {
    char buf[MAX_PATH * 2] = {};
    GetModuleFileNameA(nullptr, buf, sizeof(buf) - 1);
    return buf;
}

// DACL granting Everyone generic-all, so the elevated client can connect.
static SECURITY_ATTRIBUTES* pipe_sa() {
    static SECURITY_ATTRIBUTES sa{};
    static bool init = false;
    if (!init) {
        PSECURITY_DESCRIPTOR sd = nullptr;
        if (ConvertStringSecurityDescriptorToSecurityDescriptorA(
                "D:(A;;GA;;;WD)", SDDL_REVISION_1, &sd, nullptr)) {
            sa.nLength = sizeof(sa);
            sa.lpSecurityDescriptor = sd;
            sa.bInheritHandle = FALSE;
        }
        init = true;
    }
    return (sa.lpSecurityDescriptor || sa.nLength) ? &sa : nullptr;
}

bool elevate_agent(std::string& err) {
    std::lock_guard<std::mutex> lk(g_agent_mtx);
    if (agent_connected()) return true;

    if (current_process_elevated()) {
        err = "process is already elevated; agent not required";
        return false;
    }

    std::string pipe = "\\\\.\\pipe\\cheatmcp_agent_" +
                       std::to_string(GetCurrentProcessId()) + "_" +
                       std::to_string(GetTickCount64());

    // 1) parent creates the pipe server first
    HANDLE srv = CreateNamedPipeA(
        pipe.c_str(),
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1, 1 << 20, 1 << 20, 0, pipe_sa());
    if (srv == INVALID_HANDLE_VALUE) {
        err = "CreateNamedPipe failed: " + win32_error_string(GetLastError());
        return false;
    }

    // 2) launch this same exe elevated; it connects as client
    std::string params = "--agent \"" + pipe + "\"";
    SHELLEXECUTEINFOA sei{};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
    sei.lpVerb = "runas";
    std::string exe = exe_path();
    sei.lpFile = exe.c_str();
    sei.lpParameters = params.c_str();
    sei.nShow = SW_HIDE;

    if (!ShellExecuteExA(&sei)) {
        DWORD e = GetLastError();
        CloseHandle(srv);
        err = "ShellExecuteEx(runas) failed: " + win32_error_string(e) +
              (e == ERROR_CANCELLED ? " (UAC declined)" : "");
        return false;
    }
    g_proc = sei.hProcess;

    // 3) accept the connection with a timeout (ConnectNamedPipe in a helper thread)
    std::atomic<bool> connected{false};
    std::thread connector([&]() {
        BOOL ok = ConnectNamedPipe(srv, nullptr);
        if (!ok && GetLastError() == ERROR_PIPE_CONNECTED) ok = TRUE;
        connected.store(ok != FALSE);
    });

    for (int i = 0; i < 300 && !connected.load(); ++i) {
        if (g_proc && WaitForSingleObject(g_proc, 0) == WAIT_OBJECT_0) break;
        Sleep(100);
    }

    if (connected.load()) {
        if (connector.joinable()) connector.join();
        g_pipe = srv;
        g_readbuf.clear();
        return true;
    }

    // failure: unblock the connector, clean up
    CloseHandle(srv);
    if (connector.joinable()) connector.join();
    err = "elevated agent did not connect (UAC declined, or pipe blocked)";
    return false;
}

static bool pipe_read_line(std::string& out, DWORD timeout_ms) {
    ULONGLONG start = GetTickCount64();
    while (true) {
        size_t pos = g_readbuf.find('\n');
        if (pos != std::string::npos) {
            out = g_readbuf.substr(0, pos);
            g_readbuf.erase(0, pos + 1);
            return true;
        }
        char chunk[8192];
        DWORD rd = 0;
        if (!ReadFile(g_pipe, chunk, sizeof(chunk), &rd, nullptr) || rd == 0) return false;
        g_readbuf.append(chunk, rd);
        if (timeout_ms && GetTickCount64() - start > timeout_ms) return false;
    }
}

Json agent_call(const std::string& tool, const Json& args) {
    std::lock_guard<std::mutex> lk(g_agent_mtx);
    if (!agent_connected()) {
        Json e = Json::obj();
        e.set("error", "elevated agent not connected — call elevate() first");
        return e;
    }

    Json req = Json::obj();
    req.set("tool", tool);
    req.set("args", args);
    std::string line = req.dump() + "\n";

    DWORD wr = 0;
    if (!WriteFile(g_pipe, line.data(), (DWORD)line.size(), &wr, nullptr)) {
        Json e = win32_error_json(GetLastError(), "agent pipe write");
        return e;
    }

    std::string resp;
    if (!pipe_read_line(resp, 120000)) {
        Json e = Json::obj();
        e.set("error", "no response from elevated agent (timeout or pipe closed)");
        return e;
    }

    try {
        return Json::parse(resp);
    } catch (const std::exception& ex) {
        Json e = Json::obj();
        e.set("error", std::string("bad agent response: ") + ex.what());
        return e;
    }
}

void agent_shutdown() {
    std::lock_guard<std::mutex> lk(g_agent_mtx);
    if (g_pipe != INVALID_HANDLE_VALUE) {
        CloseHandle(g_pipe);
        g_pipe = INVALID_HANDLE_VALUE;
    }
    if (g_proc) {
        WaitForSingleObject(g_proc, 2000);
        CloseHandle(g_proc);
        g_proc = nullptr;
    }
}

Json elevated_status() {
    Json j = Json::obj();
    j.set("process_elevated", current_process_elevated());
    j.set("agent_connected", agent_connected());
    j.set("agent_alive", agent_alive());
    j.set("route_enabled", elevated_route_enabled());
    j.set("debug_privilege", enable_debug_privilege());
    return j;
}

// -----------------------------------------------------------------------------
// agent side (runs elevated, connects as pipe client)
// -----------------------------------------------------------------------------
void run_agent_loop(const std::string& pipe_name) {
    enable_debug_privilege();
    register_all_tools();
    runtime_start();

    HANDLE pipe = INVALID_HANDLE_VALUE;
    for (int i = 0; i < 300; ++i) {
        pipe = CreateFileA(pipe_name.c_str(), GENERIC_READ | GENERIC_WRITE, 0,
                           nullptr, OPEN_EXISTING, 0, nullptr);
        if (pipe != INVALID_HANDLE_VALUE) break;
        Sleep(100);
    }
    if (pipe == INVALID_HANDLE_VALUE) { runtime_stop(); return; }

    std::string buf;
    char chunk[8192];
    while (true) {
        DWORD rd = 0;
        if (!ReadFile(pipe, chunk, sizeof(chunk), &rd, nullptr) || rd == 0) break;
        buf.append(chunk, rd);

        size_t pos;
        while ((pos = buf.find('\n')) != std::string::npos) {
            std::string line = buf.substr(0, pos);
            buf.erase(0, pos + 1);
            if (line.empty()) continue;

            Json resp = Json::obj();
            try {
                Json req = Json::parse(line);
                std::string tool = req.has("tool") ? req.at("tool").as_s() : "";
                Json args = req.has("args") ? req.at("args") : Json::obj();
                ToolResult tr = registry().call(tool, args);
                resp.set("is_error", tr.is_error);
                resp.set("text", tr.text);
                resp.set("structured", tr.structured);
            } catch (const std::exception& e) {
                resp.set("is_error", true);
                resp.set("text", std::string("agent error: ") + e.what());
                resp.set("structured", Json::obj());
            }
            std::string out = resp.dump() + "\n";
            DWORD wr = 0;
            WriteFile(pipe, out.data(), (DWORD)out.size(), &wr, nullptr);
        }
    }

    runtime_stop();
    CloseHandle(pipe);
}

} // namespace cmcp
