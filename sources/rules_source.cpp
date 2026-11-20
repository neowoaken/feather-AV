#include "sources/rules_source.h"

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

SourceResult RulesSource::inspect(const FileFacts& facts) const {
    SourceResult result;
    auto add = [&result](std::string id, Severity sev, Category category,
                         int weight, std::string detail) {
        result.signals.push_back(Signal{"rules", std::move(id), sev, category,
                                        weight, std::move(detail)});
    };

    // ---- filename ---------------------------------------------------------
    const std::string name = toUtf8(facts.path.filename());
    const std::string nameLower = lower(name);

    // U+202E RIGHT-TO-LEFT OVERRIDE, used to disguise extensions.
    if (name.find("\xE2\x80\xAE") != std::string::npos) {
        add("name.rtl_override", Severity::Malicious, Category::Suspicious, 90,
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
                    add("name.double_extension", Severity::Unwanted, Category::Suspicious, 30,
                        "double extension: " + inner + "." + ext);
                }
            }
        }
    }

    // ---- PE structure -----------------------------------------------------
    const PeInfo& pe = facts.pe;
    if (!pe.valid) {
        if (facts.size >= 2) {
            std::ifstream head(facts.path, std::ios::binary);
            char mz[2] = {};
            if (head.read(mz, 2) && mz[0] == 'M' && mz[1] == 'Z') {
                add("pe.malformed", Severity::Info, Category::Suspicious, 2,
                    "starts with MZ but PE headers are malformed");
            }
        }
        return result;
    }

    if (pe.hasWritableExecutableSection) {
        add("pe.rwx_section", Severity::Unwanted, Category::Suspicious, 15,
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
        // "packed therefore malicious" is exactly the false positive we exist
        // to avoid.
        add("pe.high_entropy_exec", Severity::Info, Category::Packer, 5,
            "high-entropy executable section (packed or compressed)");
    }

    if (pe.overlaySize > (1u << 20) && pe.overlaySize > facts.size / 4) {
        add("pe.large_overlay", Severity::Info, Category::Suspicious, 3,
            "large appended overlay: " + std::to_string(pe.overlaySize) +
                " bytes");
    }

    if (pe.hasNoImports && !pe.sections.empty()) {
        add("pe.no_imports", Severity::Info, Category::Packer, 4,
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
        add("pe.injection_capable", Severity::Unwanted, Category::Injector, 20,
            "imports capable of injecting code into other processes");
    }

    if (imports("minidumpwritedump")) {
        add("pe.process_dump_capable", Severity::Unwanted, Category::HackTool, 15,
            "can dump process memory (credential-dumping capability)");
    }

    return result;
}

} // namespace feather
