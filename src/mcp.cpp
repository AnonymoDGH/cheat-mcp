// MCP server core: JSON-RPC 2.0 over stdio (newline-delimited messages).
#include "cheatmcp.hpp"

#include <iostream>
#include <string>
#include <exception>

namespace cmcp {

// =============================================================================
// registry
// =============================================================================
void Registry::add(const std::string& name, const std::string& desc, Json sch, ToolFn fn) {
    Tool t;
    t.name = name;
    t.description = desc;
    t.schema = std::move(sch);
    t.fn = std::move(fn);
    tools_[name] = std::move(t);
}

ToolResult Registry::call(const std::string& name, const Json& args) const {
    auto it = tools_.find(name);
    if (it == tools_.end()) {
        ToolResult r;
        r.is_error = true;
        Json j = Json::obj();
        j.set("error", "unknown tool: " + name);
        r.structured = j;
        r.text = j.dump();
        return r;
    }
    try {
        return it->second.fn(args);
    } catch (const std::exception& e) {
        ToolResult r;
        r.is_error = true;
        Json j = Json::obj();
        j.set("error", std::string("exception: ") + e.what());
        r.structured = j;
        r.text = j.dump();
        return r;
    } catch (...) {
        ToolResult r;
        r.is_error = true;
        Json j = Json::obj();
        j.set("error", "unknown exception");
        r.structured = j;
        r.text = j.dump();
        return r;
    }
}

Registry& registry() {
    static Registry r;
    return r;
}

// =============================================================================
// JSON-RPC
// =============================================================================
static Json rpc_result(const Json& id, Json result) {
    Json r = Json::obj();
    r.set("jsonrpc", "2.0");
    r["id"] = id;
    r.set("result", std::move(result));
    return r;
}

static Json rpc_error(const Json& id, int code, const std::string& message) {
    Json r = Json::obj();
    r.set("jsonrpc", "2.0");
    r["id"] = id;
    Json err = Json::obj();
    err.set("code", code);
    err.set("message", message);
    r.set("error", std::move(err));
    return r;
}

static Json handle_request(const Json& req, bool& is_notification) {
    is_notification = false;

    Json id = req.has("id") ? req.at("id") : Json();
    std::string method = req.has("method") ? req.at("method").as_s() : "";

    if (!req.has("id")) is_notification = true;

    Json params = req.has("params") ? req.at("params") : Json::obj();

    // ---- initialize ----
    if (method == "initialize") {
        std::string pv = "2024-11-05";
        if (params.has("protocolVersion")) pv = params.at("protocolVersion").as_s();

        Json result = Json::obj();
        result.set("protocolVersion", pv);
        Json caps = Json::obj();
        caps.set("tools", Json::obj());
        result.set("capabilities", std::move(caps));

        Json info = Json::obj();
        info.set("name", "cheat-mcp");
        info.set("version", "1.0.0");
        info.set("title", "cheat-mcp — memory manipulation toolkit");
        result.set("serverInfo", std::move(info));
        result.set("instructions",
            "Low-level game memory toolkit: process/module enumeration, read/write/scan, "
            "pointer chains, DLL injection (loadlibrary/nt/hijack/apc/wndhook/manualmap), "
            "IAT hooking, speedhack, anti-cheat detection and handle stripping, network tools.");
        return rpc_result(id, std::move(result));
    }

    // ---- notifications (no reply) ----
    if (method == "notifications/initialized" || method == "initialized") {
        is_notification = true;
        return Json();
    }
    if (method == "notifications/cancelled") {
        is_notification = true;
        return Json();
    }

    // ---- ping ----
    if (method == "ping") {
        return rpc_result(id, Json::obj());
    }

    // ---- tools/list ----
    if (method == "tools/list") {
        Json tools = Json::arr();
        for (auto& kv : registry().all()) {
            Json t = Json::obj();
            t.set("name", kv.second.name);
            t.set("description", kv.second.description);
            t.set("inputSchema", kv.second.schema);
            tools.push(std::move(t));
        }
        Json result = Json::obj();
        result.set("tools", std::move(tools));
        return rpc_result(id, std::move(result));
    }

    // ---- tools/call ----
    if (method == "tools/call") {
        std::string name = params.has("name") ? params.at("name").as_s() : "";
        Json args = params.has("arguments") ? params.at("arguments") : Json::obj();

        ToolResult tr = registry().call(name, args);

        Json content = Json::arr();
        Json text = Json::obj();
        text.set("type", "text");
        text.set("text", tr.text);
        content.push(std::move(text));

        Json result = Json::obj();
        result.set("content", std::move(content));
        result.set("isError", tr.is_error);
        if (!tr.structured.is_null()) result.set("structuredContent", tr.structured);
        return rpc_result(id, std::move(result));
    }

    if (is_notification) return Json();
    return rpc_error(id, -32601, "method not found: " + method);
}

// =============================================================================
// stdio loop
// =============================================================================
int run_server() {
    std::ios::sync_with_stdio(false);

    std::string line;
    while (std::getline(std::cin, line)) {
        // trim
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n' || line.back() == ' '))
            line.pop_back();
        if (line.empty()) continue;

        Json req;
        try {
            req = Json::parse(line);
        } catch (const std::exception& e) {
            Json err = rpc_error(Json(), -32700, std::string("parse error: ") + e.what());
            std::cout << err.dump() << "\n" << std::flush;
            continue;
        }

        bool note = false;
        Json resp = handle_request(req, note);
        if (!note && !resp.is_null()) {
            std::cout << resp.dump() << "\n" << std::flush;
        }
    }
    return 0;
}

} // namespace cmcp
