#pragma once

#include <string>
#include <string_view>

namespace feather {

// Verdict tiers. A file's tier is the strongest signal any source produced.
enum class Severity { None = 0, Info = 1, Unwanted = 2, Malicious = 3 };

const char* severityName(Severity severity);

// What kind of thing a source thinks it found. Deliberately closer to
// Malwarebytes' vocabulary than to a boolean "bad file": users care whether
// they are looking at a hack tool, adware or a stealer, because that decides
// what they want to do with it.
enum class Category {
    None = 0,
    Unknown,
    Malware,
    HackTool,
    Adware,
    Pua,
    Packer,
    Injector,
    Dropper,
    Spyware,
    Stealer,
    Miner,
    Ransomware,
    Trojan,
    Worm,
    Virus,
    Test,
    Suspicious
};

// Stable lowercase id for JSON / policy files, e.g. "hacktool".
const char* categoryId(Category category);

// Human label, e.g. "HackTool".
const char* categoryLabel(Category category);

// Parses an id or label, case-insensitive. Accepts "hacktool", "HackTool",
// "hack-tool" and "hack tool".
bool parseCategory(std::string_view text, Category& out);

// One detection source's opinion about one file. Sources never decide the
// final verdict; the fusion layer does. This is what lets a ClamAV
// "PUA.HackTool.*" signature become `unwanted` instead of a deletion.
struct Signal {
    std::string source;  // "rules", "ioc", "clamav", "yara"
    std::string id;      // stable rule id, e.g. "pe.rwx_section"
    Severity severity = Severity::Info;
    Category category = Category::Unknown;
    int weight = 0;      // display/ordering only
    std::string detail;  // human-readable reason
};

} // namespace feather
