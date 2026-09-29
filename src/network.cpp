#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#include "cheatmcp.hpp"

#include <cstring>
#include <cstdio>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace cmcp {

static bool wsa_ready() {
    static bool init = false;
    static bool ok = false;
    if (!init) {
        WSADATA w{};
        ok = WSAStartup(MAKEWORD(2, 2), &w) == 0;
        init = true;
    }
    return ok;
}

static std::string fmt_v4(DWORD addr) {
    in_addr a{};
    a.S_un.S_addr = addr;
    char buf[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &a, buf, sizeof(buf) - 1);
    return buf;
}

static std::string fmt_v6(const UCHAR* addr) {
    char buf[INET6_ADDRSTRLEN] = {};
    inet_ntop(AF_INET6, (void*)addr, buf, sizeof(buf) - 1);
    return buf;
}

static int port_nbo(DWORD p) { return ntohs((u_short)p); }

static const char* tcp_state(DWORD s) {
    switch (s) {
        case 1: return "CLOSED"; case 2: return "LISTEN"; case 3: return "SYN_SENT";
        case 4: return "SYN_RECV"; case 5: return "ESTABLISHED"; case 6: return "FIN_WAIT1";
        case 7: return "FIN_WAIT2"; case 8: return "CLOSE_WAIT"; case 9: return "CLOSING";
        case 10: return "LAST_ACK"; case 11: return "TIME_WAIT"; case 12: return "DELETE_TCB";
        default: return "?";
    }
}

// =============================================================================
// connection table
// =============================================================================
Json net_connections(int pid_filter) {
    Json r = Json::obj();
    Json arr = Json::arr();
    wsa_ready();

    // ---- TCP IPv4 ----
    DWORD size = 0;
    if (GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER) {
        std::vector<uint8_t> buf(size);
        if (GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            auto* t = (MIB_TCPTABLE_OWNER_PID*)buf.data();
            for (DWORD k = 0; k < t->dwNumEntries; ++k) {
                auto& row = t->table[k];
                if (pid_filter >= 0 && (int)row.dwOwningPid != pid_filter) continue;
                Json e = Json::obj();
                e.set("proto", "tcp4");
                e.set("local", fmt_v4(row.dwLocalAddr) + ":" + std::to_string(port_nbo(row.dwLocalPort)));
                e.set("remote", fmt_v4(row.dwRemoteAddr) + ":" + std::to_string(port_nbo(row.dwRemotePort)));
                e.set("state", tcp_state(row.dwState));
                e.set("pid", (long long)row.dwOwningPid);
                arr.push(std::move(e));
            }
        }
    }

    // ---- TCP IPv6 ----
    size = 0;
    if (GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER) {
        std::vector<uint8_t> buf(size);
        if (GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            auto* t = (MIB_TCP6TABLE_OWNER_PID*)buf.data();
            for (DWORD k = 0; k < t->dwNumEntries; ++k) {
                auto& row = t->table[k];
                if (pid_filter >= 0 && (int)row.dwOwningPid != pid_filter) continue;
                Json e = Json::obj();
                e.set("proto", "tcp6");
                e.set("local", std::string("[") + fmt_v6(row.ucLocalAddr) + "]:" + std::to_string(port_nbo(row.dwLocalPort)));
                e.set("remote", std::string("[") + fmt_v6(row.ucRemoteAddr) + "]:" + std::to_string(port_nbo(row.dwRemotePort)));
                e.set("state", tcp_state(row.dwState));
                e.set("pid", (long long)row.dwOwningPid);
                arr.push(std::move(e));
            }
        }
    }

    // ---- UDP IPv4 ----
    size = 0;
    if (GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == ERROR_INSUFFICIENT_BUFFER) {
        std::vector<uint8_t> buf(size);
        if (GetExtendedUdpTable(buf.data(), &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
            auto* t = (MIB_UDPTABLE_OWNER_PID*)buf.data();
            for (DWORD k = 0; k < t->dwNumEntries; ++k) {
                auto& row = t->table[k];
                if (pid_filter >= 0 && (int)row.dwOwningPid != pid_filter) continue;
                Json e = Json::obj();
                e.set("proto", "udp4");
                e.set("local", fmt_v4(row.dwLocalAddr) + ":" + std::to_string(port_nbo(row.dwLocalPort)));
                e.set("remote", "");
                e.set("state", "");
                e.set("pid", (long long)row.dwOwningPid);
                arr.push(std::move(e));
            }
        }
    }

    r.set("count", (long long)arr.size());
    r.set("connections", std::move(arr));
    return r;
}

// =============================================================================
// DNS
// =============================================================================
Json net_resolve(const std::string& host) {
    Json r = Json::obj();
    r.set("host", host);
    Json arr = Json::arr();
    wsa_ready();

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0) {
        r.set("error", "resolution failed");
        return r;
    }
    for (auto* p = res; p; p = p->ai_next) {
        char buf[INET6_ADDRSTRLEN] = {};
        if (p->ai_family == AF_INET)
            inet_ntop(AF_INET, &((sockaddr_in*)p->ai_addr)->sin_addr, buf, sizeof(buf) - 1);
        else if (p->ai_family == AF_INET6)
            inet_ntop(AF_INET6, &((sockaddr_in6*)p->ai_addr)->sin6_addr, buf, sizeof(buf) - 1);
        else continue;
        arr.push(std::string(buf));
    }
    freeaddrinfo(res);
    r.set("addresses", std::move(arr));
    return r;
}

// =============================================================================
// simple senders
// =============================================================================
bool net_send_udp(const std::string& host, uint16_t port, const std::vector<uint8_t>& data, std::string& err) {
    if (!wsa_ready()) { err = "winsock init failed"; return false; }
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) { err = "socket failed"; return false; }

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &dst.sin_addr) != 1) {
        addrinfo hints{}; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_DGRAM;
        addrinfo* res = nullptr;
        if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) {
            closesocket(s); err = "bad address"; return false;
        }
        dst.sin_addr = ((sockaddr_in*)res->ai_addr)->sin_addr;
        freeaddrinfo(res);
    }
    int sent = sendto(s, (const char*)data.data(), (int)data.size(), 0,
                      (sockaddr*)&dst, sizeof(dst));
    closesocket(s);
    if (sent < 0) { err = "sendto failed: " + std::to_string(WSAGetLastError()); return false; }
    return true;
}

bool net_send_tcp(const std::string& host, uint16_t port, const std::vector<uint8_t>& data, std::string& err) {
    if (!wsa_ready()) { err = "winsock init failed"; return false; }
    addrinfo hints{}; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0 || !res) {
        err = "bad address"; return false;
    }
    SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) { freeaddrinfo(res); err = "socket failed"; return false; }
    if (connect(s, res->ai_addr, (int)res->ai_addrlen) != 0) {
        closesocket(s); freeaddrinfo(res);
        err = "connect failed: " + std::to_string(WSAGetLastError());
        return false;
    }
    freeaddrinfo(res);
    int sent = send(s, (const char*)data.data(), (int)data.size(), 0);
    closesocket(s);
    if (sent < 0) { err = "send failed"; return false; }
    return true;
}

// =============================================================================
// raw IP capture (SIO_RCVALL) — needs admin
// =============================================================================
Json net_capture(const std::string& filter_ip, int max_packets, int timeout_ms) {
    Json r = Json::obj();
    Json arr = Json::arr();
    if (max_packets <= 0) max_packets = 20;
    if (timeout_ms <= 0) timeout_ms = 1500;
    if (!wsa_ready()) { r.set("error", "winsock init failed"); return r; }

    SOCKET s = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (s == INVALID_SOCKET) { r.set("error", "raw socket failed (run as admin)"); return r; }

    // bind to the first local IPv4 address
    char hostname[256] = {};
    gethostname(hostname, sizeof(hostname) - 1);
    addrinfo hints{}; hints.ai_family = AF_INET;
    addrinfo* res = nullptr;
    if (getaddrinfo(hostname, nullptr, &hints, &res) != 0 || !res) {
        closesocket(s); r.set("error", "cannot resolve local host"); return r;
    }
    sockaddr_in local = *(sockaddr_in*)res->ai_addr;
    freeaddrinfo(res);

    if (bind(s, (sockaddr*)&local, sizeof(local)) != 0) {
        closesocket(s); r.set("error", "bind failed"); return r;
    }
    DWORD on = 1;
    if (WSAIoctl(s, SIO_RCVALL, &on, sizeof(on), nullptr, 0, nullptr, nullptr, nullptr) != 0) {
        closesocket(s); r.set("error", "SIO_RCVALL failed (admin required)"); return r;
    }

    DWORD tv = timeout_ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    std::vector<uint8_t> buf(65536);
    for (int got = 0; got < max_packets;) {
        int n = recv(s, (char*)buf.data(), (int)buf.size(), 0);
        if (n <= 0) break;
        auto* ip = (unsigned char*)buf.data();
        if (n < 20) continue;
        int ihl = (ip[0] & 0x0F) * 4;
        char src[32], dst[32];
        snprintf(src, sizeof src, "%u.%u.%u.%u", ip[12], ip[13], ip[14], ip[15]);
        snprintf(dst, sizeof dst, "%u.%u.%u.%u", ip[16], ip[17], ip[18], ip[19]);
        int proto = ip[9];
        if (!filter_ip.empty() && filter_ip != src && filter_ip != dst) continue;

        Json e = Json::obj();
        e.set("src", src);
        e.set("dst", dst);
        e.set("proto", proto);
        e.set("length", (long long)n);
        e.set("header", to_hex(buf.data(), (size_t)ihl));
        e.set("payload_len", (long long)(n - ihl));
        arr.push(std::move(e));
        ++got;
    }

    closesocket(s);
    r.set("count", (long long)arr.size());
    r.set("packets", std::move(arr));
    return r;
}

// =============================================================================
// raw IP send (spoofing-capable with IP_HDRINCL) — needs admin
// =============================================================================
Json net_send_raw_ip(uint32_t dst_ip_be, const std::vector<uint8_t>& ip_packet) {
    Json r = Json::obj();
    if (!wsa_ready()) { r.set("error", "winsock init failed"); return r; }

    SOCKET s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (s == INVALID_SOCKET) { r.set("error", "raw socket failed (admin required)"); return r; }

    DWORD on = 1;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, (const char*)&on, sizeof(on)) != 0) {
        closesocket(s); r.set("error", "IP_HDRINCL failed"); return r;
    }
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_addr.S_un.S_addr = dst_ip_be;
    int sent = sendto(s, (const char*)ip_packet.data(), (int)ip_packet.size(), 0,
                      (sockaddr*)&dst, sizeof(dst));
    closesocket(s);
    if (sent < 0) { r.set("error", "sendto failed: " + std::to_string(WSAGetLastError())); return r; }
    r.set("sent", (long long)sent);
    return r;
}

} // namespace cmcp
