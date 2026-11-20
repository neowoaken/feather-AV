#pragma once

#include <string>

namespace feather {

// Verdict tiers. A file's tier is the strongest signal any source produced.
enum class Severity { None = 0, Info = 1, Unwanted = 2, Malicious = 3 };

const char* severityName(Severity severity);

// One detection source's opinion about one file. Sources never decide the
// final verdict; the fusion layer does. This is what lets a ClamAV
// "PUA.HackTool.*" signature become `unwanted` instead of a deletion.
struct Signal {
    std::string source;  // "rules", "ioc", "clamav", "yara"
    std::string id;      // stable rule id, e.g. "pe.rwx_section"
    Severity severity = Severity::Info;
    int weight = 0;      // display/ordering only
    std::string detail;  // human-readable reason
};

} // namespace feather
