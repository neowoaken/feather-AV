#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace feather::cli {

struct QuarantineEntry {
    std::string timestamp;
    std::string sha256;
    std::string category;
    std::uint64_t size = 0;
    std::string originalPath;
};

// Explicit, user-initiated quarantine. Nothing in a scan ever calls this.
// Files are copied, re-hashed, verified, and only then is the original
// removed; the stored object gets a .q extension so it cannot be executed.
class Quarantine {
public:
    static std::filesystem::path defaultRoot();

    explicit Quarantine(std::filesystem::path root);

    bool add(const std::filesystem::path& file, const std::string& sha256Hex,
             const std::string& categoryId, const std::string& reason,
             std::string& error);

    bool restore(const std::string& sha256Hex, std::filesystem::path& restoredTo,
                 std::string& error);

    std::vector<QuarantineEntry> list(std::string& error) const;

    const std::filesystem::path& root() const { return root_; }

private:
    std::filesystem::path manifestPath() const;
    std::filesystem::path objectPath(const std::string& sha256Hex) const;

    std::filesystem::path root_;
};

} // namespace feather::cli
