#pragma once

#include <cstddef>
#include <filesystem>
#include <string>
#include <string_view>
#include <unordered_map>

#include "engine/sha256.h"

namespace feather {

struct IocEntry {
    Digest digest{};
    std::string label;
};

// Hash-only IOC database. Deliberately no filename / pattern / "heuristic"
// entries here: those are the signals that produce false positives on
// legitimate tools, and they do not belong in a known-bad list.
class IocDatabase {
public:
    static IocDatabase loadFromFile(const std::filesystem::path& path,
                                    std::string& error);

    const IocEntry* find(const Digest& digest) const;
    std::size_t size() const { return entries_.size(); }

private:
    std::unordered_map<std::string, IocEntry> entries_; // key: lowercase hex
};

} // namespace feather
