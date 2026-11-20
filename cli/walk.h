#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <vector>

namespace feather::cli {

struct WalkOptions {
    // 0 = unlimited.
    std::uint32_t maxDepth = 0;
};

// Returns regular files under `root` (or `root` itself when it is a file).
// Directory symlinks/reparse points are not followed, so this cannot loop.
std::vector<std::filesystem::path> collectFiles(const std::filesystem::path& root,
                                                const WalkOptions& options,
                                                std::size_t& skipped);

} // namespace feather::cli
