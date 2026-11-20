#include "cli/walk.h"

#include <system_error>

namespace fs = std::filesystem;

namespace feather::cli {

std::vector<fs::path> collectFiles(const fs::path& root,
                                   const WalkOptions& options,
                                   std::size_t& skipped) {
    std::vector<fs::path> files;
    skipped = 0;

    std::error_code ec;
    const fs::file_status status = fs::status(root, ec);
    if (ec || !fs::exists(status)) return files;

    if (fs::is_regular_file(status)) {
        files.push_back(root);
        return files;
    }
    if (!fs::is_directory(status)) return files;

    fs::recursive_directory_iterator it(
        root, fs::directory_options::skip_permission_denied, ec);
    if (ec) return files;

    const fs::recursive_directory_iterator end;
    for (; it != end; it.increment(ec)) {
        if (ec) {
            ++skipped;
            ec.clear();
            continue;
        }

        const fs::directory_entry& entry = *it;

        std::error_code entryEc;
        if (entry.is_symlink(entryEc) || entryEc) {
            ++skipped;
            if (entry.is_directory(entryEc)) it.disable_recursion_pending();
            continue;
        }

        if (options.maxDepth != 0 &&
            static_cast<std::uint32_t>(it.depth()) + 1 >= options.maxDepth) {
            it.disable_recursion_pending();
        }

        if (entry.is_regular_file(entryEc) && !entryEc) {
            files.push_back(entry.path());
        }
    }

    return files;
}

} // namespace feather::cli
