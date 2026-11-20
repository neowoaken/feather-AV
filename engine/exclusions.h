#pragma once

#include <filesystem>
#include <string>
#include <vector>

#include "engine/sha256.h"

namespace feather {

// User-controlled tolerance list. Two forms:
//
//   sha256 <64 hex>   [note]   -- trust this exact file
//   path   <glob>     [note]   -- trust everything matching, e.g. C:\Games\*
//
// Suppression NEVER applies to a Malicious verdict. A known-bad hash stays
// known-bad even if a path rule covers it. That is deliberate: the whole point
// of the tier model is that "this is a game fix" is not a get-out-of-jail card
// for a stealer.
class Exclusions {
public:
    static Exclusions loadFromFile(const std::filesystem::path& path,
                                   std::vector<std::string>& warnings);

    // Returns the matching rule's reason, or empty if nothing matched.
    std::string match(const Digest& digest, const std::string& utf8Path) const;

    std::size_t size() const { return rules_.size(); }

private:
    struct Rule {
        bool byHash = false;
        std::string hashHex;  // lowercase
        std::string glob;     // lowercase
        std::string reason;
    };
    std::vector<Rule> rules_;
};

// True if `text` matches a `*` / `?` glob (case-insensitive).
bool globMatch(const std::string& pattern, const std::string& text);

} // namespace feather
