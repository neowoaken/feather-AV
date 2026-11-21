// Feather AV real-time protection service.
//
// Connects to the featherflt minifilter's communication port and answers one
// verdict per executable open. Detection is layered: the same Engine used by
// the CLI (built-in rules + IOC list + optional clamd over a local socket).
// Malicious and unwanted verdicts are denied at the kernel and moved to a
// restorable quarantine before the reply is sent. Nothing is ever wiped here.
//
// Failure is fail-open and visible: if the filter, clamd, or the file itself
// cannot be read, the open proceeds and the degraded state is written to
// %PROGRAMDATA%\Feather\realtime-status.json for the GUI to display.

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include "cli/quarantine.h"
#include "driver/featherflt/protocol.h"
#include "engine/engine.h"
#include "verdict/signal.h"

namespace fs = std::filesystem;
using Clock = std::chrono::system_clock;
using Steady = std::chrono::steady_clock;

namespace {

// Minimal mirrors of fltuser.h / fltUserStructures.h. The service loads
// fltLib.dll at runtime instead of requiring the WDK headers and import
// library, so it builds anywhere the Windows SDK is available.
struct FeatherMessageHeader {
    ULONG ReplyLength;
    ULONGLONG MessageId;
};

struct FeatherReplyHeader {
    LONG Status;
    ULONGLONG MessageId;
};

using ConnectPortFn = HRESULT(WINAPI*)(
    LPCWSTR, DWORD, LPCVOID, DWORD, LPSECURITY_ATTRIBUTES, HANDLE*);
using GetMessageFn = HRESULT(WINAPI*)(
    HANDLE, FeatherMessageHeader*, DWORD, LPOVERLAPPED);
using ReplyMessageFn = HRESULT(WINAPI*)(HANDLE, FeatherReplyHeader*, DWORD);

ConnectPortFn g_connectPort = nullptr;
GetMessageFn g_getMessage = nullptr;
ReplyMessageFn g_replyMessage = nullptr;

bool loadFltLib() {
    if (g_connectPort != nullptr) return true;
    HMODULE library = LoadLibraryW(L"fltLib.dll");
    if (library == nullptr) return false;
    g_connectPort = reinterpret_cast<ConnectPortFn>(
        GetProcAddress(library, "FilterConnectCommunicationPort"));
    g_getMessage = reinterpret_cast<GetMessageFn>(
        GetProcAddress(library, "FilterGetMessage"));
    g_replyMessage = reinterpret_cast<ReplyMessageFn>(
        GetProcAddress(library, "FilterReplyMessage"));
    return g_connectPort != nullptr && g_getMessage != nullptr &&
           g_replyMessage != nullptr;
}

constexpr const char* kVersion = "0.4.0";
constexpr const wchar_t* kServiceName = L"FeatherRT";
constexpr DWORD kPortRetryMs = 5000;
constexpr DWORD kStatusIntervalMs = 5000;
constexpr std::size_t kMaxEventBytes = 2u << 20;

SERVICE_STATUS g_serviceStatus{};
SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
HANDLE g_stopEvent = nullptr;
HANDLE g_portLostEvent = nullptr;
std::atomic<bool> g_stop{false};

// --------------------------------------------------------------- small helpers

std::wstring envWide(const wchar_t* name) {
    DWORD n = GetEnvironmentVariableW(name, nullptr, 0);
    if (n == 0) return {};
    std::wstring value(n - 1, L'\0');
    GetEnvironmentVariableW(name, value.data(), n);
    return value;
}

std::wstring moduleWide() {
    std::wstring buf(MAX_PATH, L'\0');
    for (;;) {
        DWORD n = GetModuleFileNameW(nullptr, buf.data(), static_cast<DWORD>(buf.size()));
        if (n == 0) return {};
        if (n < buf.size()) {
            buf.resize(n);
            return buf;
        }
        buf.resize(buf.size() * 2);
    }
}

fs::path programDataDir() {
    const std::wstring value = envWide(L"PROGRAMDATA");
    return value.empty() ? fs::path(L"C:\\ProgramData") : fs::path(value);
}

fs::path localAppDataDir() {
    const std::wstring value = envWide(L"LOCALAPPDATA");
    return value.empty() ? programDataDir() : fs::path(value);
}

fs::path appRoot() {
    fs::path module = moduleWide();
    if (module.empty()) return {};
    fs::path dir = module.parent_path();
    if (dir.filename() == L"bin") dir = dir.parent_path();
    return dir;
}

std::string toUtf8(std::wstring_view text) {
    if (text.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, text.data(),
        static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string out(static_cast<std::size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
        out.data(), n, nullptr, nullptr);
    return out;
}

std::wstring widen(std::string_view text) {
    if (text.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, text.data(),
        static_cast<int>(text.size()), nullptr, 0);
    if (n <= 0) return {};
    std::wstring out(static_cast<std::size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
        out.data(), n);
    return out;
}

std::string utf8(const fs::path& path) { return toUtf8(path.native()); }

std::string lower(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return text;
}

std::wstring lower(std::wstring text) {
    std::transform(text.begin(), text.end(), text.begin(), [](wchar_t c) {
        return static_cast<wchar_t>(std::tolower(static_cast<unsigned short>(c)));
    });
    return text;
}

std::string trim(std::string text) {
    const auto first = text.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const auto last = text.find_last_not_of(" \t\r\n");
    return text.substr(first, last - first + 1);
}

std::string jsonEscape(std::string_view text) {
    std::string out;
    out.reserve(text.size() + 8);
    for (unsigned char c : text) {
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (c < 0x20) {
                static const char* hex = "0123456789abcdef";
                out += "\\u00";
                out += hex[(c >> 4) & 0xf];
                out += hex[c & 0xf];
            } else {
                out += static_cast<char>(c);
            }
        }
    }
    return out;
}

std::string nowIso() {
    const std::time_t t = Clock::to_time_t(Clock::now());
    std::tm tm{};
    localtime_s(&tm, &t);
    char buf[32] = {};
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm);
    return buf;
}

void writeAtomic(const fs::path& path, const std::string& content) {
    std::error_code ec;
    fs::create_directories(path.parent_path(), ec);
    const fs::path tmp = path.string() + ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) {
            std::cerr << "feathersvc: cannot write " << utf8(path) << "\n";
            return;
        }
        out << content;
    }
    if (!MoveFileExW(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        std::cerr << "feathersvc: cannot publish " << utf8(path)
                  << " (" << GetLastError() << ")\n";
    }
}

bool parseInt(const std::string& text, long long& out) {
    try {
        std::size_t used = 0;
        out = std::stoll(text, &used);
        return used == text.size();
    } catch (...) {
        return false;
    }
}

// --------------------------------------------------------------- configuration

fs::path findRulesFile(const fs::path& root, const wchar_t* name) {
    fs::path dir = root;
    for (int i = 0; i < 4 && !dir.empty(); ++i) {
        const fs::path candidate = dir / "rules" / name;
        if (fs::exists(candidate)) return candidate;
        if (dir == dir.parent_path()) break;
        dir = dir.parent_path();
    }
    return root / "rules" / name;
}

struct Config {
    feather::ClamAvEndpoint clam{"127.0.0.1", 3310};
    bool clamEnabled = true;
    fs::path ioc;
    fs::path allow;
    fs::path quarantine;
    bool quarantineUnwanted = true;
    DWORD workerThreads = 4;
    int cacheTtlSeconds = 600;
};

Config loadConfig(const fs::path& root, std::vector<std::string>& notes) {
    Config cfg;
    cfg.ioc = findRulesFile(root, L"ioc.sample.txt");
    cfg.allow = localAppDataDir() / "Feather" / "allow.txt";
    cfg.quarantine = feather::cli::Quarantine::systemRoot();

    const fs::path file = programDataDir() / "Feather" / "realtime.conf";
    std::ifstream in(file);
    if (!in) {
        notes.push_back("no realtime.conf; using defaults (" + utf8(file) + ")");
        return cfg;
    }

    std::string line;
    while (std::getline(in, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        const auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        const std::string key = trim(line.substr(0, eq));
        const std::string value = trim(line.substr(eq + 1));
        if (value.empty()) continue;

        if (key == "clamd") {
            if (lower(value) == "none" || lower(value) == "off") {
                cfg.clamEnabled = false;
            } else {
                const auto colon = value.rfind(':');
                long long port = 0;
                if (colon == std::string::npos || colon == 0 ||
                    !parseInt(value.substr(colon + 1), port) ||
                    port <= 0 || port > 65535) {
                    notes.push_back("invalid clamd endpoint: " + value);
                } else {
                    cfg.clam.host = value.substr(0, colon);
                    cfg.clam.port = static_cast<std::uint16_t>(port);
                    cfg.clamEnabled = true;
                }
            }
        } else if (key == "ioc") {
            cfg.ioc = widen(value);
        } else if (key == "allow") {
            cfg.allow = widen(value);
        } else if (key == "quarantine") {
            cfg.quarantine = widen(value);
        } else if (key == "quarantine_unwanted") {
            cfg.quarantineUnwanted = lower(value) != "false" && value != "0";
        } else if (key == "threads") {
            long long n = 0;
            if (parseInt(value, n) && n >= 1 && n <= 16) {
                cfg.workerThreads = static_cast<DWORD>(n);
            }
        } else if (key == "cache_ttl") {
            long long n = 0;
            if (parseInt(value, n) && n >= 60 && n <= 86400) {
                cfg.cacheTtlSeconds = static_cast<int>(n);
            }
        }
    }
    return cfg;
}

// --------------------------------------------------------------- clamd probing

std::once_flag g_wsaOnce;

bool clamdReachable(const Config& cfg) {
    if (!cfg.clamEnabled) return false;
    std::call_once(g_wsaOnce, [] { WSADATA data; WSAStartup(MAKEWORD(2, 2), &data); });

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* list = nullptr;
    const std::string port = std::to_string(cfg.clam.port);
    if (getaddrinfo(cfg.clam.host.c_str(), port.c_str(), &hints, &list) != 0) {
        return false;
    }

    bool reachable = false;
    for (addrinfo* ai = list; ai != nullptr; ai = ai->ai_next) {
        SOCKET s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == INVALID_SOCKET) continue;
        u_long nonblocking = 1;
        ioctlsocket(s, FIONBIO, &nonblocking);
        connect(s, ai->ai_addr, static_cast<int>(ai->ai_addrlen));
        fd_set writeSet;
        FD_ZERO(&writeSet);
        FD_SET(s, &writeSet);
        timeval tv{0, 200000};  // 200 ms
        const int ready = select(0, nullptr, &writeSet, nullptr, &tv);
        if (ready > 0) {
            int error = 0;
            int size = sizeof(error);
            getsockopt(s, SOL_SOCKET, SO_ERROR,
                reinterpret_cast<char*>(&error), &size);
            reachable = (error == 0);
        }
        closesocket(s);
        if (reachable) break;
    }
    freeaddrinfo(list);
    return reachable;
}

// --------------------------------------------------------------- decision core

struct VerdictResult {
    ULONG verdict = FEATHER_VERDICT_ALLOW;
    ULONG flags = 0;
    std::string severity = "clean";
    std::string category = "none";
    std::string source = "local";
    std::string detail = "";
    std::string sha256 = "";
    std::string note = "";
};

class Realtime {
public:
    explicit Realtime(Config cfg) : cfg_(std::move(cfg)), quarantine_(cfg_.quarantine) {
        std::string iocError;
        const auto ioc = feather::IocDatabase::loadFromFile(cfg_.ioc, iocError);
        if (!iocError.empty()) notes_.push_back("IOC: " + iocError);

        std::vector<std::string> allowWarnings;
        const auto allow = feather::Exclusions::loadFromFile(cfg_.allow, allowWarnings);
        for (const auto& warning : allowWarnings) notes_.push_back("allow: " + warning);

        feather::EngineConfig engineConfig;
        engineConfig.ioc = ioc;
        engineConfig.exclusions = allow;
        if (cfg_.clamEnabled) engineConfig.clamd = cfg_.clam;
        engine_ = std::make_unique<feather::Engine>(std::move(engineConfig));
        scope_ = engine_->sourceScope();
        iocCount_ = ioc.size();

        writeStatus();
    }

    const Config& config() const { return cfg_; }

    // Dev/test entry point: run the exact same decision path the filter uses,
    // without needing a loaded kernel driver. Used by tests/realtime.ps1.
    VerdictResult probePath(const fs::path& path) {
        FEATHER_SCAN_REQUEST request{};
        std::wstring text = path.wstring();
        if (text.size() >= FEATHER_PATH_MAX - 1) {
            text.resize(FEATHER_PATH_MAX - 1);
        }
        request.ProcessId = 0;  // no trusted process in probe mode
        request.PathLength = static_cast<ULONG>(text.size() * sizeof(WCHAR));
        std::memcpy(request.Path, text.data(), request.PathLength);
        return decide(request);
    }

    VerdictResult decide(const FEATHER_SCAN_REQUEST& request) {
        VerdictResult result;

        const std::wstring pathText(request.Path,
            std::min<std::size_t>(request.PathLength / sizeof(WCHAR),
                                  FEATHER_PATH_MAX - 1));
        if (request.PathLength == 0 || (request.PathLength % sizeof(WCHAR)) != 0 ||
            request.PathLength >= sizeof(request.Path)) {
            result.note = "malformed path in filter request";
            result.flags |= FEATHER_REPLY_FLAG_DEGRADED;
            ++failOpen_;
            writeEvent(request, result);
            return result;
        }

        const fs::path path(pathText);
        const std::string key = lower(utf8(path));
        if (isTrustedProcess(request.ProcessId)) {
            result.note = "trusted Feather process";
            return result;
        }

        const auto at = Steady::now();
        const auto ageSeconds = [&](Steady::time_point when) {
            return std::chrono::duration_cast<std::chrono::seconds>(at - when).count();
        };

        {
            std::lock_guard<std::mutex> lock(cacheMutex_);
            const auto found = cache_.find(key);
            if (found != cache_.end() &&
                ageSeconds(found->second.at) < cfg_.cacheTtlSeconds) {
                const CacheEntry& entry = found->second;
                std::error_code ec;
                const bool exists = fs::exists(path, ec);
                if (entry.verdict == FEATHER_VERDICT_QUARANTINE && !exists) {
                    result.verdict = FEATHER_VERDICT_BLOCK;
                    result.flags |= FEATHER_REPLY_FLAG_CACHED;
                    result.severity = entry.severity;
                    result.category = entry.category;
                    result.source = "cache";
                    result.detail = "previously quarantined";
                    ++blocks_;
                    writeEvent(request, result);
                    return result;
                }
                if (exists) {
                    const auto size = fs::file_size(path, ec);
                    const auto mtime = fs::last_write_time(path, ec).time_since_epoch().count();
                    if (!ec && size == entry.size &&
                        static_cast<std::int64_t>(mtime) == entry.mtime) {
                        result.verdict = entry.verdict;
                        result.flags |= FEATHER_REPLY_FLAG_CACHED;
                        result.severity = entry.severity;
                        result.category = entry.category;
                        result.source = "cache";
                        result.detail = "cached verdict";
                        if (result.verdict == FEATHER_VERDICT_BLOCK ||
                            result.verdict == FEATHER_VERDICT_QUARANTINE) {
                            ++blocks_;
                        }
                        writeEvent(request, result);
                        return result;
                    }
                }
            }
        }

        ++scans_;
        // Capture the identity before the scan: the file may be moved into
        // quarantine below, and we still want a cache entry that blocks every
        // later open of this path until the file changes.
        const FileStamp before = fileStamp(path);
        const feather::Finding finding = engine_->analyze(path);
        result.sha256 = finding.sha256;

        if (!finding.error.empty()) {
            result.note = finding.error;
            result.flags |= FEATHER_REPLY_FLAG_DEGRADED;
            ++failOpen_;
            cache(key, before, result);
            writeEvent(request, result);
            return result;
        }

        const feather::Severity severity = finding.effectiveVerdict();
        result.severity = feather::severityName(severity);
        result.category = feather::categoryId(finding.category);
        if (!finding.hits.empty()) {
            result.source = finding.hits.front().source;
            result.detail = finding.hits.front().detail;
        }
        for (const auto& warning : finding.warnings) {
            if (result.note.empty()) result.note = warning;
        }

        const bool malicious = severity == feather::Severity::Malicious;
        const bool unwanted = severity == feather::Severity::Unwanted;
        std::string quarantineError;

        if (malicious || (unwanted && cfg_.quarantineUnwanted)) {
            std::string reason = "real-time " + result.severity + " (" + result.source + ")";
            if (quarantine_.add(path, finding.sha256, result.category, reason,
                                quarantineError)) {
                result.verdict = FEATHER_VERDICT_QUARANTINE;
                ++quarantines_;
            } else {
                // Deny anyway: a file we could not move must not be executed.
                result.verdict = FEATHER_VERDICT_BLOCK;
                result.note = "quarantine failed: " + quarantineError;
            }
        } else if (unwanted) {
            result.verdict = FEATHER_VERDICT_BLOCK;
        }

        if (result.verdict == FEATHER_VERDICT_BLOCK ||
            result.verdict == FEATHER_VERDICT_QUARANTINE) {
            ++blocks_;
            {
                std::lock_guard<std::mutex> lock(statsMutex_);
                lastAction_ = nowIso() + " " + result.severity + " " + utf8(path);
            }
        }

        cache(key, before, result);
        writeEvent(request, result);
        return result;
    }

    void writeStatus() {
        const bool clamUp = clamdReachable(cfg_);
        {
            std::lock_guard<std::mutex> lock(statsMutex_);
            std::ostringstream out;
            out << "{\n"
                << "  \"version\": 1,\n"
                << "  \"service\": \"running\",\n"
                << "  \"productVersion\": \"" << kVersion << "\",\n"
                << "  \"filter\": \"" << (portConnected_ ? "connected" : "not connected") << "\",\n"
                << "  \"clamav\": \"" << (clamUp ? "reachable" : (cfg_.clamEnabled ? "unreachable" : "disabled")) << "\",\n"
                << "  \"endpoint\": \"" << jsonEscape(cfg_.clam.host + ":" + std::to_string(cfg_.clam.port)) << "\",\n"
                << "  \"rules\": \"" << jsonEscape(scope_) << "\",\n"
                << "  \"iocCount\": " << iocCount_ << ",\n"
                << "  \"scans\": " << scans_.load() << ",\n"
                << "  \"blocks\": " << blocks_.load() << ",\n"
                << "  \"quarantines\": " << quarantines_.load() << ",\n"
                << "  \"failOpen\": " << failOpen_.load() << ",\n"
                << "  \"lastAction\": \"" << jsonEscape(lastAction_) << "\",\n"
                << "  \"updated\": \"" << nowIso() << "\"\n"
                << "}\n";
            writeAtomic(statusPath(), out.str());
        }
    }

    void setPortConnected(bool connected) {
        portConnected_ = connected;
        writeStatus();
    }

    static fs::path statusPath() {
        return programDataDir() / "Feather" / "realtime-status.json";
    }

    static fs::path eventsPath() {
        return programDataDir() / "Feather" / "realtime-events.jsonl";
    }

private:
    struct CacheEntry {
        std::uint64_t size = 0;
        std::int64_t mtime = 0;
        ULONG verdict = FEATHER_VERDICT_ALLOW;
        std::string severity;
        std::string category;
        Steady::time_point at{};
    };

    struct FileStamp {
        std::uint64_t size = 0;
        std::int64_t mtime = 0;
        bool ok = false;
    };

    struct PidInfo {
        bool trusted = false;
        Steady::time_point at{};
    };

    static FileStamp fileStamp(const fs::path& path) {
        FileStamp stamp;
        std::error_code ec;
        stamp.size = fs::file_size(path, ec);
        if (ec) return stamp;
        const auto mtime = fs::last_write_time(path, ec).time_since_epoch().count();
        if (ec) return stamp;
        stamp.mtime = static_cast<std::int64_t>(mtime);
        stamp.ok = true;
        return stamp;
    }

    void cache(const std::string& key, const FileStamp& stamp, const VerdictResult& result) {
        if (!stamp.ok) return;
        CacheEntry entry;
        entry.size = stamp.size;
        entry.mtime = stamp.mtime;
        entry.verdict = result.verdict;
        entry.severity = result.severity;
        entry.category = result.category;
        entry.at = Steady::now();
        std::lock_guard<std::mutex> lock(cacheMutex_);
        cache_[key] = std::move(entry);
    }

    bool isTrustedProcess(DWORD pid) {
        if (pid == GetCurrentProcessId()) return true;
        const auto now = Steady::now();
        {
            std::lock_guard<std::mutex> lock(pidMutex_);
            const auto found = pidCache_.find(pid);
            if (found != pidCache_.end() &&
                std::chrono::duration_cast<std::chrono::minutes>(now - found->second.at).count() < 5) {
                return found->second.trusted;
            }
        }

        bool trusted = false;
        HANDLE handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (handle != nullptr) {
            std::wstring image(MAX_PATH, L'\0');
            DWORD length = static_cast<DWORD>(image.size());
            if (QueryFullProcessImageNameW(handle, 0, image.data(), &length) && length > 0) {
                image.resize(length);
                const fs::path exe(image);
                const fs::path root = appRoot();
                if (!root.empty()) {
                    const std::wstring prefix = lower(root.wstring()) + L"\\";
                    trusted = lower(exe.wstring()).rfind(prefix, 0) == 0;
                }
            }
            CloseHandle(handle);
        }

        std::lock_guard<std::mutex> lock(pidMutex_);
        pidCache_[pid] = PidInfo{trusted, now};
        if (pidCache_.size() > 512) pidCache_.clear();
        return trusted;
    }

    void writeEvent(const FEATHER_SCAN_REQUEST& request, const VerdictResult& result) {
        const std::wstring path(request.Path,
            std::min<std::size_t>(request.PathLength / sizeof(WCHAR),
                                  FEATHER_PATH_MAX - 1));
        const char* action =
            result.verdict == FEATHER_VERDICT_QUARANTINE ? "quarantined" :
            result.verdict == FEATHER_VERDICT_BLOCK ? "blocked" : "allowed";
        std::ostringstream out;
        out << "{\"timestamp\":\"" << nowIso() << '"'
            << ",\"pid\":" << request.ProcessId
            << ",\"path\":\"" << jsonEscape(toUtf8(path)) << '"'
            << ",\"action\":\"" << action << '"'
            << ",\"verdict\":" << result.verdict
            << ",\"severity\":\"" << result.severity << '"'
            << ",\"category\":\"" << result.category << '"'
            << ",\"source\":\"" << result.source << '"'
            << ",\"detail\":\"" << jsonEscape(result.detail) << '"'
            << ",\"sha256\":\"" << result.sha256 << '"'
            << ",\"note\":\"" << jsonEscape(result.note) << "\"}\n";

        std::lock_guard<std::mutex> lock(eventMutex_);
        std::error_code ec;
        const auto file = eventsPath();
        fs::create_directories(file.parent_path(), ec);
        if (fs::exists(file, ec) && fs::file_size(file, ec) > kMaxEventBytes) {
            fs::rename(file, file.string() + ".1", ec);
        }
        std::ofstream outFile(file, std::ios::app | std::ios::binary);
        if (outFile) outFile << out.str();
    }

    Config cfg_;
    std::unique_ptr<feather::Engine> engine_;
    feather::cli::Quarantine quarantine_;
    std::string scope_;
    std::size_t iocCount_ = 0;
    std::vector<std::string> notes_;

    std::mutex cacheMutex_;
    std::unordered_map<std::string, CacheEntry> cache_;
    std::mutex pidMutex_;
    std::unordered_map<DWORD, PidInfo> pidCache_;
    std::mutex eventMutex_;
    std::mutex statsMutex_;

    std::atomic<unsigned long long> scans_{0};
    std::atomic<unsigned long long> blocks_{0};
    std::atomic<unsigned long long> quarantines_{0};
    std::atomic<unsigned long long> failOpen_{0};
    std::atomic<bool> portConnected_{false};
    std::string lastAction_;
};

// --------------------------------------------------------------- port plumbing

struct MessageSlot {
    FeatherMessageHeader header;
    FEATHER_SCAN_REQUEST request;
    OVERLAPPED overlapped;
};

struct ReplyPacket {
    FeatherReplyHeader header;
    FEATHER_SCAN_REPLY reply;
};

struct WorkerContext {
    HANDLE port = nullptr;
    HANDLE completion = nullptr;
    DWORD slotBodySize = 0;
    Realtime* realtime = nullptr;
};

DWORD WINAPI WorkerThread(LPVOID parameter) {
    WorkerContext* ctx = static_cast<WorkerContext*>(parameter);
    for (;;) {
        DWORD bytes = 0;
        ULONG_PTR key = 0;
        LPOVERLAPPED overlapped = nullptr;
        const BOOL ok = GetQueuedCompletionStatus(ctx->completion, &bytes, &key,
                                                  &overlapped, INFINITE);
        if (!ok) {
            const DWORD error = GetLastError();
            if (g_stop || error == ERROR_OPERATION_ABORTED ||
                error == ERROR_INVALID_HANDLE) {
                break;
            }
            continue;
        }
        if (overlapped == nullptr) {
            if (g_stop) break;
            continue;
        }

        MessageSlot* slot = CONTAINING_RECORD(overlapped, MessageSlot, overlapped);
        VerdictResult result;
        if (!g_stop && bytes >= sizeof(FeatherMessageHeader)) {
            result = ctx->realtime->decide(slot->request);
        } else {
            result.flags |= FEATHER_REPLY_FLAG_DEGRADED;
        }

        ReplyPacket reply{};
        reply.header.Status = 0;
        reply.header.MessageId = slot->header.MessageId;
        reply.reply.Verdict = result.verdict;
        reply.reply.Flags = result.flags;
        g_replyMessage(ctx->port, &reply.header, sizeof(reply));

        if (g_stop) break;

        std::memset(&slot->overlapped, 0, sizeof(OVERLAPPED));
        const HRESULT hr = g_getMessage(ctx->port, &slot->header,
            ctx->slotBodySize, &slot->overlapped);
        if (FAILED(hr) && hr != HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {
            SetEvent(g_portLostEvent);
            break;
        }
    }
    return 0;
}

void setServiceStatus(DWORD state, DWORD win32Exit = 0, DWORD waitHint = 0) {
    g_serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_serviceStatus.dwCurrentState = state;
    g_serviceStatus.dwWin32ExitCode = win32Exit;
    g_serviceStatus.dwCheckPoint = (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING)
        ? g_serviceStatus.dwCheckPoint + 1 : 0;
    g_serviceStatus.dwWaitHint = waitHint;
    g_serviceStatus.dwControlsAccepted = state == SERVICE_RUNNING
        ? (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN) : 0;
    SetServiceStatus(g_statusHandle, &g_serviceStatus);
}

void WINAPI serviceHandler(DWORD control) {
    if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN) {
        g_stop = true;
        setServiceStatus(SERVICE_STOP_PENDING, 0, 10000);
        SetEvent(g_stopEvent);
    }
}

void ensureEvents() {
    if (g_stopEvent == nullptr) g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (g_portLostEvent == nullptr) g_portLostEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
}

void runService() {
    setServiceStatus(SERVICE_START_PENDING, 0, 10000);
    ensureEvents();

    std::unique_ptr<Realtime> realtime;
    try {
        std::vector<std::string> configNotes;
        Config cfg = loadConfig(appRoot(), configNotes);
        for (const auto& note : configNotes) {
            std::cerr << "feathersvc: " << note << "\n";
        }
        realtime = std::make_unique<Realtime>(std::move(cfg));
    } catch (const std::exception& ex) {
        std::cerr << "feathersvc: initialisation failed: " << ex.what() << "\n";
        setServiceStatus(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, 0);
        return;
    }

    std::thread statusThread([&] {
        while (!g_stop) {
            realtime->writeStatus();
            if (WaitForSingleObject(g_stopEvent, kStatusIntervalMs) == WAIT_OBJECT_0) break;
        }
    });

    if (!loadFltLib()) {
        // fltLib.dll is part of Windows, but be honest if it is unavailable.
        std::cerr << "feathersvc: fltLib.dll is unavailable; filter port disabled\n";
        setServiceStatus(SERVICE_RUNNING);
        WaitForSingleObject(g_stopEvent, INFINITE);
        g_stop = true;
        realtime->writeStatus();
        statusThread.join();
        setServiceStatus(SERVICE_STOPPED, 0, 0);
        return;
    }

    while (!g_stop) {
        HANDLE port = nullptr;
        const HRESULT hr = g_connectPort(FEATHER_PORT_NAME, 0,
            nullptr, 0, nullptr, &port);
        if (FAILED(hr) || port == nullptr) {
            realtime->setPortConnected(false);
            setServiceStatus(SERVICE_RUNNING);
            if (WaitForSingleObject(g_stopEvent, kPortRetryMs) == WAIT_OBJECT_0) break;
            continue;
        }

        const DWORD threads = realtime->config().workerThreads;
        std::vector<std::unique_ptr<MessageSlot>> slots;
        std::vector<HANDLE> workers;
        HANDLE completion = nullptr;
        const DWORD bodySize = static_cast<DWORD>(offsetof(MessageSlot, overlapped));
        bool healthy = true;

        completion = CreateIoCompletionPort(port, nullptr, 0, threads);
        if (completion == nullptr) healthy = false;

        if (healthy) {
            ResetEvent(g_portLostEvent);
            slots.resize(threads);
            for (auto& slot : slots) slot = std::make_unique<MessageSlot>();
            WorkerContext context{port, completion, bodySize, realtime.get()};
            for (auto& slot : slots) {
                std::memset(slot.get(), 0, sizeof(MessageSlot));
                const HRESULT getHr = g_getMessage(port, &slot->header,
                    bodySize, &slot->overlapped);
                if (FAILED(getHr) && getHr != HRESULT_FROM_WIN32(ERROR_IO_PENDING)) {
                    healthy = false;
                    break;
                }
            }
            if (healthy) {
                for (DWORD i = 0; i < threads; ++i) {
                    HANDLE thread = CreateThread(nullptr, 0, WorkerThread, &context, 0, nullptr);
                    if (thread == nullptr) { healthy = false; break; }
                    workers.push_back(thread);
                }
            }
        }

        if (healthy) {
            realtime->setPortConnected(true);
            setServiceStatus(SERVICE_RUNNING);
            const HANDLE waits[] = {g_stopEvent, g_portLostEvent};
            const DWORD signaled = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
            if (signaled == WAIT_OBJECT_0) g_stop = true;
            CancelIoEx(port, nullptr);
        } else {
            realtime->setPortConnected(false);
        }

        for (HANDLE thread : workers) {
            WaitForSingleObject(thread, INFINITE);
            CloseHandle(thread);
        }
        if (completion != nullptr) CloseHandle(completion);
        CloseHandle(port);

        if (!g_stop) {
            realtime->setPortConnected(false);
            if (WaitForSingleObject(g_stopEvent, kPortRetryMs) == WAIT_OBJECT_0) break;
        }
    }

    g_stop = true;
    realtime->writeStatus();
    statusThread.join();
    setServiceStatus(SERVICE_STOPPED, 0, 0);
}

void WINAPI serviceMain(DWORD, LPWSTR*) {
    g_statusHandle = RegisterServiceCtrlHandlerW(kServiceName, serviceHandler);
    if (g_statusHandle == nullptr) return;
    runService();
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    ensureEvents();
    if (argc > 2 && std::wcscmp(argv[1], L"--probe") == 0) {
        std::vector<std::string> notes;
        Config cfg = loadConfig(appRoot(), notes);
        Realtime realtime(std::move(cfg));
        const VerdictResult result = realtime.probePath(fs::path(argv[2]));
        std::cout << "verdict=" << result.verdict
                  << " severity=" << result.severity
                  << " category=" << result.category
                  << " source=" << result.source
                  << " action=" << result.note << "\n";
        return 0;
    }
    const bool console = argc > 1 && std::wcscmp(argv[1], L"--console") == 0;
    if (console) {
        std::cout << "feathersvc " << kVersion
                  << " (console mode; press Ctrl+C to stop)\n";
        runService();
        return 0;
    }

    SERVICE_TABLE_ENTRYW table[] = {
        {const_cast<wchar_t*>(kServiceName), serviceMain},
        {nullptr, nullptr}
    };
    if (!StartServiceCtrlDispatcherW(table)) {
        std::cerr << "StartServiceCtrlDispatcher failed: " << GetLastError() << "\n";
        return 1;
    }
    return 0;
}
