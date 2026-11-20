#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <unordered_map>

namespace feather::cli {

struct CacheEntry {
    std::uint64_t size = 0;
    std::int64_t mtime = 0;  // filesystem clock ticks
    std::string sha256;
    int verdict = 0;         // feather::Severity as int
    std::string sources;     // engine source scope this verdict was produced under
};

// Flat-file cache of (path, size, mtime) -> (sha256, verdict). Unchanged files
// with a known verdict are skipped entirely on the next run, which is where
// the "lightweight" claim actually comes from.
class HashCache {
public:
    bool load(const std::filesystem::path& path, std::string& warning);
    bool save(const std::filesystem::path& path, std::string& warning) const;

    // Returns nullptr when the path is unknown, or when the cached verdict was
    // produced with a different set of detection sources.
    const CacheEntry* find(const std::string& utf8Path,
                           const std::string& sourceScope) const;
    void put(std::string utf8Path, CacheEntry entry);

    std::size_t size() const { return entries_.size(); }

private:
    std::unordered_map<std::string, CacheEntry> entries_;
};

} // namespace feather::cli
