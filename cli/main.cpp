#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

#include "cli/cache.h"
#include "cli/quarantine.h"
#include "cli/walk.h"
#include "engine/engine.h"

namespace fs = std::filesystem;

using feather::Category;
using feather::Engine;
using feather::EngineOptions;
using feather::Finding;
using feather::IocDatabase;
using feather::Severity;
using feather::categoryId;
using feather::categoryLabel;
using feather::severityName;

namespace {

constexpr const char* kVersion = "0.3.0";

struct Options {
    std::wstring command;
    fs::path target;
    fs::path iocFile;
    fs::path allowFile;
    fs::path cacheFile;
    fs::path jsonFile;
    std::optional<feather::ClamAvEndpoint> clamd;
    fs::path quarantineDir;
    std::string categoryId;
    std::string reason;
    unsigned threads = 0;
    bool all = false;
    bool quiet = false;
    bool noCache = false;
    bool help = false;
    bool version = false;
};

std::string toUtf8(const fs::path& p) {
    const std::u8string u8 = p.u8string();
    return std::string(reinterpret_cast<const char*>(u8.data()), u8.size());
}

bool parseEndpoint(const fs::path& text, feather::ClamAvEndpoint& out) {
    const std::string s = toUtf8(text);
    const std::size_t colon = s.rfind(':');
    if (colon == std::string::npos || colon == 0 || colon + 1 >= s.size()) {
        return false;
    }
    out.host = s.substr(0, colon);
    try {
        const unsigned long port = std::stoul(s.substr(colon + 1));
        if (port == 0 || port > 65535) return false;
        out.port = static_cast<std::uint16_t>(port);
    } catch (...) {
        return false;
    }
    return true;
}

fs::path defaultCachePath() {
#ifdef _WIN32
    wchar_t buf[MAX_PATH] = {};
    const DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", buf, MAX_PATH);
    if (n > 0 && n < MAX_PATH) {
        return fs::path(std::wstring(buf, n)) / L"Feather" / L"cache.tsv";
    }
#endif
    if (const char* home = std::getenv("HOME")) {
        return fs::path(home) / ".cache" / "feather" / "cache.tsv";
    }
    return fs::path("feather-cache.tsv");
}

void printUsage() {
    std::cout <<
        "feather " << kVersion << " -- lightweight file scanner\n"
        "\n"
        "usage:\n"
        "  feather scan <path> [options]\n"
        "  feather hash <path>\n"
        "  feather quarantine <path> [--category <id>] [--reason <text>]\n"
        "  feather restore <sha256>\n"
        "  feather quarantine-list\n"
        "  feather version\n"
        "\n"
        "options:\n"
        "  --ioc <file>     known-bad SHA-256 list   (rules/ioc.sample.txt)\n"
        "  --allow <file>   user exclusions          (rules/allow.sample.txt)\n"
        "  --cache <file>   hash cache location (default: user profile)\n"
        "  --no-cache       do not read or write the cache\n"
        "  --json <file>    write findings as JSON\n"
        "  --clamd <host:port>  add a local clamd (ClamAV) as a source\n"
        "  --threads <n>    worker threads (default: CPU count)\n"
        "  --quarantine-dir <dir>  override the quarantine location\n"
        "  --category <id>  category id for quarantine (hacktool, adware, ...)\n"
        "  --reason <text>  note stored in the quarantine manifest\n"
        "  --all            also list info-level and allowed findings\n"
        "  --quiet          no progress output\n"
        "\n"
        "verdicts:\n"
        "  malicious   known-bad hash or filename spoofing      -> block\n"
        "  unwanted    suspicious capability, not proof          -> warn\n"
        "  info        structural oddity, not a verdict          -> note\n"
        "  clean       nothing known\n"
        "\n"
        "exit codes: 0 clean, 2 unwanted/malicious found, 1 usage or IO error\n";
}

bool parseArgs(const std::vector<std::wstring>& args, Options& o,
               std::string& err) {
    std::vector<std::wstring> positional;

    for (std::size_t i = 1; i < args.size(); ++i) {
        const std::wstring& a = args[i];

        auto value = [&](fs::path& out) -> bool {
            if (i + 1 >= args.size()) return false;
            out = fs::path(args[++i]);
            return true;
        };

        if (a == L"--ioc") {
            if (!value(o.iocFile)) { err = "--ioc needs a file"; return false; }
        } else if (a == L"--allow") {
            if (!value(o.allowFile)) { err = "--allow needs a file"; return false; }
        } else if (a == L"--cache") {
            if (!value(o.cacheFile)) { err = "--cache needs a file"; return false; }
        } else if (a == L"--json") {
            if (!value(o.jsonFile)) { err = "--json needs a file"; return false; }
        } else if (a == L"--clamd") {
            fs::path endpoint;
            if (!value(endpoint)) { err = "--clamd needs host:port"; return false; }
            feather::ClamAvEndpoint parsed;
            if (!parseEndpoint(endpoint, parsed)) {
                err = "--clamd expects host:port";
                return false;
            }
            o.clamd = parsed;
        } else if (a == L"--quarantine-dir") {
            if (!value(o.quarantineDir)) {
                err = "--quarantine-dir needs a path";
                return false;
            }
        } else if (a == L"--category") {
            if (i + 1 >= args.size()) { err = "--category needs a value"; return false; }
            o.categoryId = toUtf8(fs::path(args[++i]));
        } else if (a == L"--reason") {
            if (i + 1 >= args.size()) { err = "--reason needs a value"; return false; }
            o.reason = toUtf8(fs::path(args[++i]));
        } else if (a == L"--threads") {
            if (i + 1 >= args.size()) { err = "--threads needs a number"; return false; }
            try {
                o.threads = static_cast<unsigned>(std::stoul(args[++i]));
            } catch (...) {
                err = "--threads: not a number";
                return false;
            }
        } else if (a == L"--all") {
            o.all = true;
        } else if (a == L"--quiet") {
            o.quiet = true;
        } else if (a == L"--no-cache") {
            o.noCache = true;
        } else if (a == L"--help" || a == L"-h") {
            o.help = true;
        } else if (a == L"--version" || a == L"-V") {
            o.version = true;
        } else if (!a.empty() && a[0] == L'-') {
            err = "unknown option: " + toUtf8(fs::path(a));
            return false;
        } else {
            positional.push_back(a);
        }
    }

    if (o.version) return true;
    if (o.help || positional.empty()) {
        o.help = true;
        return true;
    }

    o.command = positional[0];
    if (o.command == L"version") {
        o.version = true;
        return true;
    }
    static const std::vector<std::wstring> kCommands = {
        L"scan", L"hash", L"quarantine", L"restore", L"quarantine-list"};
    if (std::find(kCommands.begin(), kCommands.end(), o.command) ==
        kCommands.end()) {
        err = "unknown command: " + toUtf8(fs::path(positional[0]));
        return false;
    }
    if (o.command == L"quarantine-list") return true;
    if (positional.size() < 2) {
        err = "command needs an argument";
        return false;
    }
    o.target = fs::path(positional[1]);
    return true;
}

std::string jsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    return out;
}

std::string findingJson(const Finding& f) {
    std::string out = "{";
    out += "\"path\":\"" + jsonEscape(toUtf8(f.path)) + "\",";
    out += "\"size\":" + std::to_string(f.size) + ",";
    out += "\"sha256\":\"" + f.sha256 + "\",";
    out += "\"verdict\":\"" + std::string(severityName(f.effectiveVerdict())) + "\",";
    out += "\"category\":\"" + std::string(categoryId(f.category)) + "\",";
    out += "\"categoryLabel\":\"" + std::string(categoryLabel(f.category)) + "\",";
    out += "\"suppressed\":";
    out += f.suppressed ? "true" : "false";
    out += ",";
    out += "\"cached\":";
    out += f.cached ? "true" : "false";
    out += ",";
    out += "\"error\":";
    out += f.error.empty() ? "null" : ("\"" + jsonEscape(f.error) + "\"");
    out += ",\"warnings\":[";
    for (std::size_t i = 0; i < f.warnings.size(); ++i) {
        if (i > 0) out += ",";
        out += "\"" + jsonEscape(f.warnings[i]) + "\"";
    }
    out += "]";
    out += ",\"hits\":[";
    for (std::size_t i = 0; i < f.hits.size(); ++i) {
        const auto& h = f.hits[i];
        if (i > 0) out += ",";
        out += "{\"source\":\"" + jsonEscape(h.source) + "\",\"id\":\"" +
               jsonEscape(h.id) + "\",\"severity\":\"" +
               severityName(h.severity) + "\",\"category\":\"" +
               categoryId(h.category) + "\",\"weight\":" +
               std::to_string(h.weight) + ",\"detail\":\"" +
               jsonEscape(h.detail) + "\"}";
    }
    out += "]}";
    return out;
}

bool shouldReport(const Finding& f, bool all) {
    if (!f.error.empty()) return true;
    if (!f.warnings.empty()) return true;
    const Severity v = f.effectiveVerdict();
    if (v == Severity::Malicious || v == Severity::Unwanted) return true;
    if (all && (v != Severity::None || !f.hits.empty())) return true;
    return false;
}

void printFindingText(const Finding& f) {
    const Severity v = f.effectiveVerdict();
    const char* label = f.suppressed ? "allowed" : severityName(v);

    std::cout << "[" << label;
    if (f.category != Category::None) {
        std::cout << " / " << categoryLabel(f.category);
    }
    std::cout << "] " << toUtf8(f.path) << "\n";
    if (!f.error.empty()) {
        std::cout << "    error: " << f.error << "\n";
        return;
    }
    std::cout << "    sha256: " << f.sha256;
    if (f.cached) std::cout << " (cached)";
    std::cout << "\n";
    if (f.suppressed) {
        std::cout << "    excluded: " << f.suppressionReason << "\n";
    }
    for (const auto& h : f.hits) {
        std::cout << "    - [" << h.source << "] " << h.id << " ("
                  << severityName(h.severity) << ", " << categoryId(h.category)
                  << "): " << h.detail << "\n";
    }
    for (const auto& w : f.warnings) {
        std::cout << "    warning: " << w << "\n";
    }
}

} // namespace

int wmain(int argc, wchar_t** argv) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif

    Options opt;
    std::string err;

    std::vector<std::wstring> args;
    args.reserve(static_cast<std::size_t>(argc));
    for (int i = 0; i < argc; ++i) args.emplace_back(argv[i]);

    if (!parseArgs(args, opt, err)) {
        std::cerr << "error: " << err << "\n\n";
        printUsage();
        return 1;
    }
    if (opt.version) {
        std::cout << "feather " << kVersion << "\n";
        return 0;
    }
    if (opt.help) {
        printUsage();
        return 0;
    }

    const fs::path quarantineRoot = opt.quarantineDir.empty()
        ? feather::cli::Quarantine::defaultRoot()
        : opt.quarantineDir;
    feather::cli::Quarantine quarantine(quarantineRoot);

    if (opt.command == L"quarantine-list") {
        std::string error;
        const auto entries = quarantine.list(error);
        if (!error.empty()) std::cerr << "warning: " << error << "\n";
        if (entries.empty()) {
            std::cout << "quarantine is empty (" << toUtf8(quarantineRoot)
                      << ")\n";
            return 0;
        }
        for (const auto& e : entries) {
            std::cout << e.timestamp << "  " << e.category << "  " << e.size
                      << "  " << e.sha256 << "  " << e.originalPath << "\n";
        }
        std::cout << entries.size() << " item(s) in "
                  << toUtf8(quarantineRoot) << "\n";
        return 0;
    }

    if (opt.command == L"restore") {
        fs::path restored;
        std::string error;
        if (!quarantine.restore(toUtf8(opt.target), restored, error)) {
            std::cerr << "error: " << error << "\n";
            return 1;
        }
        std::cout << "restored " << toUtf8(restored) << "\n";
        return 0;
    }

    if (opt.command == L"quarantine") {
        const Engine engine;
        const Finding finding = engine.analyze(opt.target);
        if (!finding.error.empty()) {
            std::cerr << "error: " << finding.error << "\n";
            return 1;
        }
        std::string category = opt.categoryId;
        if (category.empty()) category = categoryId(finding.category);

        std::string error;
        if (!quarantine.add(opt.target, finding.sha256, category, opt.reason,
                            error)) {
            std::cerr << "error: " << error << "\n";
            return 1;
        }
        std::cout << "quarantined " << toUtf8(opt.target) << "  " << finding.sha256
                  << "  " << category << "\n";
        return 0;
    }

    if (opt.command == L"hash") {
        const Engine engine;
        const Finding finding = engine.analyze(opt.target);
        if (!finding.error.empty()) {
            std::cerr << "error: " << finding.error << "\n";
            return 1;
        }
        std::cout << finding.sha256 << "\n";
        return 0;
    }

    // ---- load databases ---------------------------------------------------
    IocDatabase ioc;
    if (!opt.iocFile.empty()) {
        std::string loadErr;
        ioc = IocDatabase::loadFromFile(opt.iocFile, loadErr);
        if (!loadErr.empty()) {
            std::cerr << "warning: " << loadErr << "\n";
        }
        if (ioc.size() == 0) {
            std::cerr << "warning: IOC database is empty\n";
        }
    }

    feather::Exclusions exclusions;
    if (!opt.allowFile.empty()) {
        std::vector<std::string> warnings;
        exclusions = feather::Exclusions::loadFromFile(opt.allowFile, warnings);
        for (const auto& w : warnings) std::cerr << "warning: " << w << "\n";
    }

    // ---- cache ------------------------------------------------------------
    feather::cli::HashCache cache;
    fs::path cachePath = opt.cacheFile.empty() ? defaultCachePath() : opt.cacheFile;
    const bool useCache = !opt.noCache;
    if (useCache) {
        std::string warning;
        cache.load(cachePath, warning);
        if (!warning.empty()) std::cerr << "warning: " << warning << "\n";
    }

    // ---- enumerate --------------------------------------------------------
    const auto started = std::chrono::steady_clock::now();

    std::size_t skipped = 0;
    feather::cli::WalkOptions walkOptions;
    const std::vector<fs::path> files =
        feather::cli::collectFiles(opt.target, walkOptions, skipped);

    if (files.empty()) {
        std::cerr << "error: nothing to scan at " << toUtf8(opt.target) << "\n";
        return 1;
    }

    // ---- scan -------------------------------------------------------------
    feather::EngineConfig engineConfig;
    engineConfig.ioc = std::move(ioc);
    engineConfig.exclusions = std::move(exclusions);
    engineConfig.clamd = opt.clamd;
    const Engine engine(std::move(engineConfig));
    const std::string cacheScope = engine.sourceScope();

    std::vector<Finding> results(files.size());
    std::vector<std::optional<feather::cli::CacheEntry>> pending(files.size());
    std::atomic<std::size_t> next{0};
    std::atomic<std::size_t> finished{0};

    unsigned threadCount = opt.threads;
    if (threadCount == 0) {
        threadCount = std::max(1u, std::thread::hardware_concurrency());
    }
    threadCount = static_cast<unsigned>(
        std::min<std::size_t>(threadCount, std::max<std::size_t>(1, files.size())));

    auto worker = [&]() {
        for (;;) {
            const std::size_t i = next.fetch_add(1, std::memory_order_relaxed);
            if (i >= files.size()) break;

            const fs::path& path = files[i];
            std::error_code ec;

            const auto sizeNow = fs::file_size(path, ec);
            std::error_code timeEc;
            const auto mtimeNow = fs::last_write_time(path, timeEc);

            if (useCache && !ec && !timeEc) {
                const std::string key = toUtf8(path);
                const auto mtime = static_cast<std::int64_t>(
                    mtimeNow.time_since_epoch().count());
                if (const auto* entry = cache.find(key, cacheScope);
                    entry != nullptr && entry->size == sizeNow &&
                    entry->mtime == mtime) {
                    Finding cached;
                    cached.path = path;
                    cached.size = sizeNow;
                    cached.sha256 = entry->sha256;
                    cached.verdict = static_cast<Severity>(entry->verdict);
                    cached.cached = true;

                    // Exclusions can change between runs, so re-apply them to
                    // cached verdicts instead of trusting the cached state.
                    if (feather::Sha256::fromHex(entry->sha256, cached.digest)) {
                        engine.applyExclusions(cached);
                    }

                    results[i] = std::move(cached);
                    finished.fetch_add(1, std::memory_order_relaxed);
                    continue;
                }
            }

            Finding finding = engine.analyze(path);

            if (useCache && finding.error.empty() && !ec && !timeEc) {
                feather::cli::CacheEntry entry;
                entry.size = sizeNow;
                entry.mtime = static_cast<std::int64_t>(
                    mtimeNow.time_since_epoch().count());
                entry.sha256 = finding.sha256;
                entry.verdict = static_cast<int>(finding.verdict);
                entry.sources = cacheScope;
                pending[i] = std::move(entry);
            }

            results[i] = std::move(finding);
            finished.fetch_add(1, std::memory_order_relaxed);
        }
    };

    std::vector<std::thread> pool;
    pool.reserve(threadCount);
    for (unsigned t = 0; t < threadCount; ++t) pool.emplace_back(worker);

    if (!opt.quiet && opt.jsonFile.empty()) {
        const std::size_t total = files.size();
        while (finished.load(std::memory_order_relaxed) < total) {
            std::cout << "\rscanned " << finished.load() << " / " << total
                      << std::flush;
            std::this_thread::sleep_for(std::chrono::milliseconds(120));
        }
    }

    for (auto& t : pool) t.join();

    if (!opt.quiet && opt.jsonFile.empty()) {
        std::cout << "\r" << std::string(48, ' ') << "\r";
    }

    if (useCache) {
        for (std::size_t i = 0; i < files.size(); ++i) {
            if (pending[i]) cache.put(toUtf8(files[i]), std::move(*pending[i]));
        }
        std::string warning;
        if (!cache.save(cachePath, warning) && !warning.empty()) {
            std::cerr << "warning: " << warning << "\n";
        }
    }

    // ---- report -----------------------------------------------------------
    std::size_t malicious = 0, unwanted = 0, info = 0, clean = 0, allowed = 0,
                errors = 0, cached = 0;

    for (const auto& f : results) {
        if (!f.error.empty()) {
            ++errors;
            continue;
        }
        if (f.cached) ++cached;
        if (f.suppressed) ++allowed;
        switch (f.effectiveVerdict()) {
            case Severity::Malicious: ++malicious; break;
            case Severity::Unwanted: ++unwanted; break;
            case Severity::Info: ++info; break;
            default: ++clean; break;
        }
    }

    if (!opt.jsonFile.empty()) {
        std::string json = "[\n";
        bool first = true;
        for (const auto& f : results) {
            if (!shouldReport(f, opt.all)) continue;
            if (!first) json += ",\n";
            json += "  " + findingJson(f);
            first = false;
        }
        json += "\n]\n";

        std::error_code ec;
        if (opt.jsonFile.has_parent_path()) {
            fs::create_directories(opt.jsonFile.parent_path(), ec);
        }
        std::ofstream out(opt.jsonFile, std::ios::binary | std::ios::trunc);
        if (!out) {
            std::cerr << "error: cannot write " << toUtf8(opt.jsonFile) << "\n";
            return 1;
        }
        out << json;
        std::cout << "wrote " << toUtf8(opt.jsonFile) << "\n";
    } else {
        for (const auto& f : results) {
            if (shouldReport(f, opt.all)) printFindingText(f);
        }
    }

    const auto elapsed = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - started);

    std::cout << "\nscanned " << files.size() << " files in " << elapsed.count()
              << "s";
    if (cached > 0) std::cout << " (" << cached << " from cache)";
    if (skipped > 0) std::cout << ", " << skipped << " skipped";
    if (errors > 0) std::cout << ", " << errors << " errors";
    if (allowed > 0) std::cout << ", " << allowed << " allowed by exclusion";
    std::cout << "\n";
    std::cout << "malicious " << malicious << " | unwanted " << unwanted
              << " | info " << info << " | clean " << clean << "\n";

    if (malicious > 0 || unwanted > 0) return 2;
    if (errors > 0) return 1;
    return 0;
}
