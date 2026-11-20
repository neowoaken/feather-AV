#include "engine/engine.h"

#include <algorithm>
#include <array>
#include <fstream>
#include <unordered_set>

namespace feather {
namespace {

std::string toUtf8(const std::filesystem::path& p) {
    const std::u8string u8 = p.u8string();
    return std::string(reinterpret_cast<const char*>(u8.data()), u8.size());
}

std::string lower(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

bool inSet(const std::unordered_set<std::string>& set, const std::string& value) {
    return set.find(value) != set.end();
}

} // namespace

const char* severityName(Severity severity) {
    switch (severity) {
        case Severity::Malicious: return "malicious";
        case Severity::Unwanted:  return "unwanted";
        case Severity::Info:      return "info";
        case Severity::None:
        default:                  return "clean";
    }
}

Engine::Engine(IocDatabase ioc, Exclusions exclusions, EngineOptions options)
    : ioc_(std::move(ioc)), exclusions_(std::move(exclusions)), options_(options) {}

Finding Engine::analyze(const std::filesystem::path& path) const {
    Finding f;
    f.path = path;

    std::error_code ec;
    const auto sizeOpt = std::filesystem::file_size(path, ec);
    if (ec) {
        f.error = "cannot stat: " + ec.message();
        return f;
    }
    f.size = static_cast<std::uint64_t>(sizeOpt);

    // ---- hash the whole file (streamed) -----------------------------------
    {
        std::ifstream in(path, std::ios::binary);
        if (!in) {
            f.error = "cannot open for reading (locked or access denied)";
            return f;
        }

        std::vector<char> buf(1u << 20);
        Sha256 hasher;
        while (in) {
            in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
            const std::streamsize got = in.gcount();
            if (got > 0) hasher.update(buf.data(), static_cast<std::size_t>(got));
        }
        f.digest = hasher.final();
        f.sha256 = Sha256::hex(f.digest);
    }

    // ---- PE structure (prefix read) ---------------------------------------
    {
        std::ifstream in(path, std::ios::binary);
        if (in) {
            const std::uint64_t want =
                std::min<std::uint64_t>(f.size, options_.peReadLimit);
            std::vector<std::uint8_t> head(static_cast<std::size_t>(want));
            if (want > 0) {
                in.read(reinterpret_cast<char*>(head.data()),
                        static_cast<std::streamsize>(want));
                head.resize(static_cast<std::size_t>(in.gcount()));
            }
            f.pe = parsePe(head.data(), head.size());
        }
    }

    std::vector<RuleHit> hits;
    auto addHit = [&hits](std::string id, Severity sev, int weight,
                          std::string detail) {
        hits.push_back(RuleHit{std::move(id), sev, weight, std::move(detail)});
    };

    // ---- known bad --------------------------------------------------------
    if (const IocEntry* entry = ioc_.find(f.digest)) {
        addHit("hash.known_bad", Severity::Malicious, 100,
               entry->label.empty() ? "matches known-bad SHA-256"
                                    : ("known bad: " + entry->label));
    }

    // ---- filename heuristics ---------------------------------------------
    const std::string name = toUtf8(path.filename());
    const std::string nameLower = lower(name);

    // U+202E RIGHT-TO-LEFT OVERRIDE, used to disguise extensions.
    if (name.find("\xE2\x80\xAE") != std::string::npos) {
        addHit("name.rtl_override", Severity::Malicious, 90,
               "right-to-left override in filename (extension spoofing)");
    }

    {
        static const std::unordered_set<std::string> dangerous = {
            "exe", "scr", "com", "bat", "cmd", "ps1", "vbs", "vbe", "js",
            "jse", "wsf", "wsh", "hta", "lnk", "pif", "msi", "cpl", "jar",
            "reg"};
        static const std::unordered_set<std::string> bait = {
            "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg",
            "jpeg", "png", "gif", "bmp", "txt", "rtf", "mp3", "mp4", "avi",
            "mkv", "zip", "rar", "7z", "iso", "img", "csv"};

        const std::size_t last = nameLower.find_last_of('.');
        if (last != std::string::npos && last > 0) {
            const std::string ext = nameLower.substr(last + 1);
            const std::size_t prev = nameLower.find_last_of('.', last - 1);
            if (prev != std::string::npos && prev > 0) {
                const std::string inner =
                    nameLower.substr(prev + 1, last - prev - 1);
                if (inSet(dangerous, ext) && inSet(bait, inner)) {
                    addHit("name.double_extension", Severity::Unwanted, 30,
                           "double extension: " + inner + "." + ext);
                }
            }
        }
    }

    // ---- PE heuristics ----------------------------------------------------
    const PeInfo& pe = f.pe;
    if (pe.valid) {
        if (pe.hasWritableExecutableSection) {
            addHit("pe.rwx_section", Severity::Unwanted, 15,
                   "section is both writable and executable");
        }

        bool bigExecSection = false;
        for (const auto& s : pe.sections) {
            if (s.executable() && s.rawSize >= 4096) {
                bigExecSection = true;
                break;
            }
        }
        if (bigExecSection && pe.maxExecutableEntropy > 7.2) {
            // Intentionally Info only. Cracked/packed games trip this, and
            // "packed therefore malicious" is exactly the false positive we
            // exist to avoid.
            addHit("pe.high_entropy_exec", Severity::Info, 5,
                   "high-entropy executable section (packed or compressed)");
        }

        if (pe.overlaySize > (1u << 20) && pe.overlaySize > f.size / 4) {
            addHit("pe.large_overlay", Severity::Info, 3,
                   "large appended overlay: " + std::to_string(pe.overlaySize) +
                       " bytes");
        }

        if (pe.hasNoImports && !pe.sections.empty()) {
            addHit("pe.no_imports", Severity::Info, 4,
                   "no import table (unusual, often packed)");
        }

        auto imports = [&pe](const std::string& fn) {
            for (const auto& imp : pe.importedFunctions) {
                const auto bang = imp.find('!');
                if (bang == std::string::npos) continue;
                if (imp.compare(bang + 1, std::string::npos, fn) == 0) return true;
            }
            return false;
        };

        const bool canWriteRemote = imports("writeprocessmemory");
        const bool canCreateRemote = imports("createremotethread") ||
                                     imports("ntcreatethreadex") ||
                                     imports("rtlcreateuserthread") ||
                                     imports("setthreadcontext") ||
                                     imports("queueuserapc");
        const bool canAllocateRemote = imports("virtualallocex") ||
                                       imports("ntallocatevirtualmemory");

        if (canWriteRemote && (canCreateRemote || canAllocateRemote)) {
            addHit("pe.injection_capable", Severity::Unwanted, 20,
                   "imports capable of injecting code into other processes");
        }

        if (imports("minidumpwritedump")) {
            addHit("pe.process_dump_capable", Severity::Unwanted, 15,
                   "can dump process memory (credential-dumping capability)");
        }
    } else if (f.size >= 2) {
        // MZ but unparsable -> truncated or malformed binary.
        std::ifstream in(path, std::ios::binary);
        char mz[2] = {};
        if (in.read(mz, 2) && mz[0] == 'M' && mz[1] == 'Z') {
            addHit("pe.malformed", Severity::Info, 2,
                   "starts with MZ but PE headers are malformed");
        }
    }

    // ---- aggregate --------------------------------------------------------
    Severity verdict = Severity::None;
    for (const auto& hit : hits) {
        if (hit.severity > verdict) verdict = hit.severity;
    }
    f.verdict = verdict;
    f.hits = std::move(hits);

    // ---- user exclusions ---------------------------------------------------
    if (f.verdict != Severity::Malicious) {
        const std::string reason = exclusions_.match(f.digest, toUtf8(path));
        if (!reason.empty()) {
            f.suppressed = true;
            f.suppressionReason = reason;
        }
    }

    return f;
}

} // namespace feather
