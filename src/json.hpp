// Minimal, self-contained JSON value + parser/serializer (C++17).
// No external dependencies: the whole MCP server stays header-only on this side.
#pragma once
#include <string>
#include <vector>
#include <utility>
#include <initializer_list>
#include <cstdint>
#include <cstdio>
#include <cmath>
#include <stdexcept>

namespace cmcp {

class Json {
public:
    enum class T { Null, Bool, Int, Dbl, Str, Arr, Obj };

    T t = T::Null;
    bool b = false;
    long long i = 0;
    double d = 0;
    std::string s;
    std::vector<Json> a;
    std::vector<std::pair<std::string, Json>> o;

    Json() = default;
    Json(std::nullptr_t) : t(T::Null) {}
    Json(bool v) : t(T::Bool), b(v) {}
    Json(int v) : t(T::Int), i(v) {}
    Json(unsigned v) : t(T::Int), i((long long)v) {}
    Json(long v) : t(T::Int), i((long long)v) {}
    Json(long long v) : t(T::Int), i(v) {}
    Json(unsigned long long v) : t(T::Int), i((long long)v) {}
    Json(double v) : t(T::Dbl), d(v) {}
    Json(float v) : t(T::Dbl), d((double)v) {}
    Json(const char* v) : t(T::Str), s(v ? v : "") {}
    Json(const std::string& v) : t(T::Str), s(v) {}
    Json(std::string&& v) : t(T::Str), s(std::move(v)) {}

    // object literal: Json{{"key", value}, ...}
    Json(std::initializer_list<std::pair<std::string, Json>> init) {
        t = T::Obj;
        for (auto& kv : init) o.emplace_back(kv.first, kv.second);
    }

    static Json arr() { Json j; j.t = T::Arr; return j; }
    static Json obj() { Json j; j.t = T::Obj; return j; }

    bool is_null() const { return t == T::Null; }
    bool is_obj()  const { return t == T::Obj; }
    bool is_arr()  const { return t == T::Arr; }
    bool is_str()  const { return t == T::Str; }
    bool is_bool() const { return t == T::Bool; }
    bool is_num()  const { return t == T::Int || t == T::Dbl; }

    void push(Json v) { t = T::Arr; a.push_back(std::move(v)); }

    void set(const std::string& k, Json v) {
        t = T::Obj;
        for (auto& kv : o) if (kv.first == k) { kv.second = std::move(v); return; }
        o.emplace_back(k, std::move(v));
    }

    const Json* find(const std::string& k) const {
        if (t != T::Obj) return nullptr;
        for (auto& kv : o) if (kv.first == k) return &kv.second;
        return nullptr;
    }

    Json& operator[](const std::string& k) {
        if (t != T::Obj) { t = T::Obj; o.clear(); }
        for (auto& kv : o) if (kv.first == k) return kv.second;
        o.emplace_back(k, Json());
        return o.back().second;
    }

    const Json& at(const std::string& k) const {
        const Json* p = find(k);
        if (!p) throw std::runtime_error("missing key: " + k);
        return *p;
    }
    bool has(const std::string& k) const { return find(k) != nullptr; }

    size_t size() const {
        if (t == T::Arr) return a.size();
        if (t == T::Obj) return o.size();
        return 0;
    }

    long long as_i() const {
        switch (t) {
            case T::Int:  return i;
            case T::Dbl:  return (long long)d;
            case T::Bool: return b ? 1 : 0;
            case T::Str:  try { return std::stoll(s, nullptr, 0); } catch (...) { return 0; }
            default:      return 0;
        }
    }
    double as_d() const {
        switch (t) {
            case T::Dbl:  return d;
            case T::Int:  return (double)i;
            case T::Str:  try { return std::stod(s); } catch (...) { return 0; }
            default:      return 0;
        }
    }
    bool as_b() const { return as_i() != 0; }

    std::string as_s() const {
        if (t == T::Str)  return s;
        if (t == T::Bool) return b ? "true" : "false";
        if (t == T::Int) { char buf[40]; std::snprintf(buf, sizeof buf, "%lld", i); return buf; }
        if (t == T::Dbl) { char buf[64]; std::snprintf(buf, sizeof buf, "%g", d); return buf; }
        return dump();
    }

    std::string dump() const { std::string out; out.reserve(256); write(out); return out; }

    // ---------- parser ----------
    static Json parse(const std::string& in) {
        Parser p{in, 0};
        p.ws();
        Json v = p.value();
        p.ws();
        return v;
    }

private:
    static void esc(std::string& out, const std::string& v) {
        out.push_back('"');
        for (char c : v) {
            switch (c) {
                case '"':  out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n";  break;
                case '\r': out += "\\r";  break;
                case '\t': out += "\\t";  break;
                case '\b': out += "\\b";  break;
                case '\f': out += "\\f";  break;
                default:
                    if ((unsigned char)c < 0x20) {
                        char buf[8];
                        std::snprintf(buf, sizeof buf, "\\u%04x", (unsigned)(unsigned char)c);
                        out += buf;
                    } else {
                        out.push_back(c);
                    }
            }
        }
        out.push_back('"');
    }

    static void num(std::string& out, double v) {
        if (std::isnan(v) || std::isinf(v)) { out += "null"; return; }
        char buf[64];
        std::snprintf(buf, sizeof buf, "%.17g", v);
        out += buf;
    }

    void write(std::string& out) const {
        switch (t) {
            case T::Null: out += "null"; break;
            case T::Bool: out += b ? "true" : "false"; break;
            case T::Int:  { char buf[40]; std::snprintf(buf, sizeof buf, "%lld", i); out += buf; } break;
            case T::Dbl:  num(out, d); break;
            case T::Str:  esc(out, s); break;
            case T::Arr: {
                out.push_back('[');
                for (size_t k = 0; k < a.size(); ++k) { if (k) out.push_back(','); a[k].write(out); }
                out.push_back(']');
                break;
            }
            case T::Obj: {
                out.push_back('{');
                for (size_t k = 0; k < o.size(); ++k) {
                    if (k) out.push_back(',');
                    esc(out, o[k].first);
                    out.push_back(':');
                    o[k].second.write(out);
                }
                out.push_back('}');
                break;
            }
        }
    }

    struct Parser {
        const std::string& src;
        size_t pos;

        [[noreturn]] void fail(const char* msg) const {
            throw std::runtime_error(std::string("json parse error: ") + msg + " at " + std::to_string(pos));
        }
        char peek() const { return pos < src.size() ? src[pos] : '\0'; }
        char next() { if (pos >= src.size()) fail("eof"); return src[pos++]; }
        void ws() { while (pos < src.size() && (src[pos]==' '||src[pos]=='\t'||src[pos]=='\n'||src[pos]=='\r')) ++pos; }

        bool lit(const char* l) {
            size_t n = std::char_traits<char>::length(l);
            if (src.compare(pos, n, l) == 0) { pos += n; return true; }
            return false;
        }

        void utf8(std::string& out, unsigned cp) {
            if (cp < 0x80) out.push_back((char)cp);
            else if (cp < 0x800) {
                out.push_back((char)(0xC0 | (cp >> 6)));
                out.push_back((char)(0x80 | (cp & 0x3F)));
            } else {
                out.push_back((char)(0xE0 | (cp >> 12)));
                out.push_back((char)(0x80 | ((cp >> 6) & 0x3F)));
                out.push_back((char)(0x80 | (cp & 0x3F)));
            }
        }

        Json string() {
            if (next() != '"') fail("expected string");
            std::string out;
            while (true) {
                char c = next();
                if (c == '"') break;
                if (c == '\\') {
                    char e = next();
                    switch (e) {
                        case '"':  out.push_back('"');  break;
                        case '\\': out.push_back('\\'); break;
                        case '/':  out.push_back('/');  break;
                        case 'n':  out.push_back('\n'); break;
                        case 'r':  out.push_back('\r'); break;
                        case 't':  out.push_back('\t'); break;
                        case 'b':  out.push_back('\b'); break;
                        case 'f':  out.push_back('\f'); break;
                        case 'u': {
                            unsigned cp = 0;
                            for (int k = 0; k < 4; ++k) {
                                char h = next();
                                cp <<= 4;
                                if (h >= '0' && h <= '9') cp |= (unsigned)(h - '0');
                                else if (h >= 'a' && h <= 'f') cp |= (unsigned)(h - 'a' + 10);
                                else if (h >= 'A' && h <= 'F') cp |= (unsigned)(h - 'A' + 10);
                                else fail("bad \\u");
                            }
                            utf8(out, cp);
                            break;
                        }
                        default: fail("bad escape");
                    }
                } else {
                    out.push_back(c);
                }
            }
            Json j; j.t = T::Str; j.s = std::move(out); return j;
        }

        Json number() {
            size_t start = pos;
            if (peek() == '-') ++pos;
            bool isdbl = false;
            while (pos < src.size()) {
                char c = src[pos];
                if (c >= '0' && c <= '9') ++pos;
                else if (c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') { isdbl = true; ++pos; }
                else break;
            }
            std::string n = src.substr(start, pos - start);
            Json j;
            if (!isdbl) {
                try { j.t = T::Int; j.i = std::stoll(n); return j; } catch (...) {}
            }
            j.t = T::Dbl; j.d = std::stod(n); return j;
        }

        Json value() {
            ws();
            char c = peek();
            if (c == '{') return object();
            if (c == '[') return array();
            if (c == '"') return string();
            if (lit("true"))  { Json j; j.t = T::Bool; j.b = true;  return j; }
            if (lit("false")) { Json j; j.t = T::Bool; j.b = false; return j; }
            if (lit("null"))  { return Json(); }
            return number();
        }

        Json array() {
            next(); // [
            Json j = Json::arr();
            ws();
            if (peek() == ']') { ++pos; return j; }
            while (true) {
                j.a.push_back(value());
                ws();
                char c = next();
                if (c == ',') { ws(); continue; }
                if (c == ']') break;
                fail("expected , or ]");
            }
            return j;
        }

        Json object() {
            next(); // {
            Json j = Json::obj();
            ws();
            if (peek() == '}') { ++pos; return j; }
            while (true) {
                ws();
                Json k = string();
                ws();
                if (next() != ':') fail("expected :");
                j.o.emplace_back(k.s, value());
                ws();
                char c = next();
                if (c == ',') continue;
                if (c == '}') break;
                fail("expected , or }");
            }
            return j;
        }
    };
};

} // namespace cmcp
