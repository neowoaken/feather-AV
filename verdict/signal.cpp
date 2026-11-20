#include "verdict/signal.h"

#include <algorithm>
#include <string>

namespace feather {

const char* severityName(Severity severity) {
    switch (severity) {
        case Severity::Malicious: return "malicious";
        case Severity::Unwanted:  return "unwanted";
        case Severity::Info:      return "info";
        case Severity::None:
        default:                  return "clean";
    }
}

const char* categoryId(Category category) {
    switch (category) {
        case Category::Malware:    return "malware";
        case Category::HackTool:   return "hacktool";
        case Category::Adware:     return "adware";
        case Category::Pua:        return "pua";
        case Category::Packer:     return "packer";
        case Category::Injector:   return "injector";
        case Category::Dropper:    return "dropper";
        case Category::Spyware:    return "spyware";
        case Category::Stealer:    return "stealer";
        case Category::Miner:      return "miner";
        case Category::Ransomware: return "ransomware";
        case Category::Trojan:     return "trojan";
        case Category::Worm:       return "worm";
        case Category::Virus:      return "virus";
        case Category::Test:       return "test";
        case Category::Suspicious: return "suspicious";
        case Category::Unknown:    return "unknown";
        case Category::None:
        default:                   return "none";
    }
}

const char* categoryLabel(Category category) {
    switch (category) {
        case Category::Malware:    return "Malware";
        case Category::HackTool:   return "HackTool";
        case Category::Adware:     return "Adware";
        case Category::Pua:        return "PUA";
        case Category::Packer:     return "Packer";
        case Category::Injector:   return "Injector";
        case Category::Dropper:    return "Dropper";
        case Category::Spyware:    return "Spyware";
        case Category::Stealer:    return "Stealer";
        case Category::Miner:      return "Miner";
        case Category::Ransomware: return "Ransomware";
        case Category::Trojan:     return "Trojan";
        case Category::Worm:       return "Worm";
        case Category::Virus:      return "Virus";
        case Category::Test:       return "Test";
        case Category::Suspicious: return "Suspicious";
        case Category::Unknown:    return "Unknown";
        case Category::None:
        default:                   return "None";
    }
}

bool parseCategory(std::string_view text, Category& out) {
    std::string s;
    s.reserve(text.size());
    for (char c : text) {
        if (c == '-' || c == ' ' || c == '_') continue;
        s.push_back(static_cast<char>((c >= 'A' && c <= 'Z') ? c - 'A' + 'a' : c));
    }

    struct Entry {
        const char* id;
        Category category;
    };
    static constexpr Entry kEntries[] = {
        {"malware", Category::Malware},   {"hacktool", Category::HackTool},
        {"adware", Category::Adware},     {"pua", Category::Pua},
        {"packer", Category::Packer},     {"injector", Category::Injector},
        {"dropper", Category::Dropper},   {"spyware", Category::Spyware},
        {"stealer", Category::Stealer},   {"miner", Category::Miner},
        {"ransomware", Category::Ransomware}, {"trojan", Category::Trojan},
        {"worm", Category::Worm},         {"virus", Category::Virus},
        {"test", Category::Test},         {"suspicious", Category::Suspicious},
        {"unknown", Category::Unknown},
    };

    for (const auto& entry : kEntries) {
        if (s == entry.id) {
            out = entry.category;
            return true;
        }
    }
    return false;
}

} // namespace feather
