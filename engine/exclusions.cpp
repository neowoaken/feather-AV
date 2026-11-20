#include "engine/exclusions.h"

#include <fstream>
#include <sstream>

namespace feather {
namespace {

std::string trim(std::string s) {
    const char* ws = " \t\r\n";
    const std::size_t b = s.find_first_not_of(ws);
    if (b == std::string::npos) return {};
    const std::size_t e = s.find_last_not_of(ws);
    return s.substr(b, e - b + 1);
}

std::string lower(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

bool isHexHash(const std::string& s) {
    if (s.size() != 64) return false;
    for (char c : s) {
        const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                        (c >= 'A' && c <= 'F');
        if (!ok) return false;
    }
    return true;
}

} // namespace

bool globMatch(const std::string& pattern, const std::string& text) {
    // Iterative wildcard match with backtracking. `*` matches any run of
    // characters, including separators -- exclusion globs are meant to be
    // permissive about directory boundaries.
    std::size_t p = 0;
    std::size_t t = 0;
    std::size_t starP = std::string::npos;
    std::size_t starT = 0;

    while (t < text.size()) {
        const char pc = p < pattern.size() ? pattern[p] : '\0';
        if (p < pattern.size() && (pc == '?' || pc == text[t])) {
            ++p;
            ++t;
        } else if (p < pattern.size() && pc == '*') {
            starP = p++;
            starT = t;
        } else if (starP != std::string::npos) {
            p = starP + 1;
            t = ++starT;
        } else {
            return false;
        }
    }
    while (p < pattern.size() && pattern[p] == '*') ++p;
    return p == pattern.size();
}

Exclusions Exclusions::loadFromFile(const std::filesystem::path& path,
                                    std::vector<std::string>& warnings) {
    Exclusions ex;

    std::ifstream in(path);
    if (!in) {
        warnings.push_back("cannot open exclusion file: " + path.string());
        return ex;
    }

    std::string line;
    std::size_t lineNo = 0;
    while (std::getline(in, line)) {
        ++lineNo;
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;

        std::istringstream ss(line);
        std::string kind;
        std::string value;
        ss >> kind >> value;

        Rule rule;
        if (kind == "sha256" && isHexHash(value)) {
            rule.byHash = true;
            rule.hashHex = lower(value);
        } else if (kind == "path" && !value.empty()) {
            rule.byHash = false;
            rule.glob = lower(value);
        } else {
            warnings.push_back("exclusions line " + std::to_string(lineNo) +
                               ": expected 'sha256 <hex>' or 'path <glob>'");
            continue;
        }

        std::string note;
        std::getline(ss, note);
        rule.reason = trim(note);
        if (rule.reason.empty()) rule.reason = "user exclusion";

        ex.rules_.push_back(std::move(rule));
    }
    return ex;
}

std::string Exclusions::match(const Digest& digest,
                              const std::string& utf8Path) const {
    const std::string hashHex = Sha256::hex(digest);
    const std::string pathLower = lower(utf8Path);

    for (const auto& rule : rules_) {
        if (rule.byHash) {
            if (rule.hashHex == hashHex) return rule.reason;
        } else if (globMatch(rule.glob, pathLower)) {
            return rule.reason;
        }
    }
    return {};
}

} // namespace feather
