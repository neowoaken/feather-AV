#include "cli/cache.h"

#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

namespace feather::cli {

namespace {

// v2 added the source-scope column. v1 lines are ignored on read (the file is
// rewritten on the next scan), because a verdict cached without knowing which
// sources ran is not trustworthy.
constexpr char kHeader[] =
    "# feather hash cache v2 (size\tmtime\tsha256\tverdict\tsources\tpath)";

std::string toUtf8(const fs::path& p) {
    const std::u8string u8 = p.u8string();
    return std::string(reinterpret_cast<const char*>(u8.data()), u8.size());
}

} // namespace

bool HashCache::load(const fs::path& path, std::string& warning) {
    std::ifstream in(path);
    if (!in) return false;  // missing cache is normal, not a warning

    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;

        const std::size_t t1 = line.find('\t');
        const std::size_t t2 = t1 == std::string::npos ? t1 : line.find('\t', t1 + 1);
        const std::size_t t3 = t2 == std::string::npos ? t2 : line.find('\t', t2 + 1);
        const std::size_t t4 = t3 == std::string::npos ? t3 : line.find('\t', t3 + 1);
        const std::size_t t5 = t4 == std::string::npos ? t4 : line.find('\t', t4 + 1);
        if (t5 == std::string::npos) continue;  // v1 or malformed: skip silently

        try {
            CacheEntry entry;
            entry.size = std::stoull(line.substr(0, t1));
            entry.mtime = std::stoll(line.substr(t1 + 1, t2 - t1 - 1));
            entry.sha256 = line.substr(t2 + 1, t3 - t2 - 1);
            entry.verdict = std::stoi(line.substr(t3 + 1, t4 - t3 - 1));
            entry.sources = line.substr(t4 + 1, t5 - t4 - 1);
            entries_[line.substr(t5 + 1)] = std::move(entry);
        } catch (const std::exception&) {
            warning = "cache: skipping unparsable line";
        }
    }
    return true;
}

bool HashCache::save(const fs::path& path, std::string& warning) const {
    std::error_code ec;
    if (path.has_parent_path()) {
        fs::create_directories(path.parent_path(), ec);
    }

    std::ostringstream out;
    out << kHeader << '\n';
    for (const auto& [key, entry] : entries_) {
        out << entry.size << '\t' << entry.mtime << '\t' << entry.sha256 << '\t'
            << entry.verdict << '\t' << entry.sources << '\t' << key << '\n';
    }

    const fs::path tmp = path.string() + ".tmp";
    {
        std::ofstream file(tmp, std::ios::binary | std::ios::trunc);
        if (!file) {
            warning = "cannot write cache: " + toUtf8(path);
            return false;
        }
        const std::string data = out.str();
        file.write(data.data(), static_cast<std::streamsize>(data.size()));
        if (!file) {
            warning = "failed while writing cache: " + toUtf8(path);
            return false;
        }
    }

    fs::remove(path, ec);
    fs::rename(tmp, path, ec);
    if (ec) {
        warning = "cannot replace cache: " + ec.message();
        fs::remove(tmp, ec);
        return false;
    }
    return true;
}

const CacheEntry* HashCache::find(const std::string& utf8Path,
                                  const std::string& sourceScope) const {
    const auto it = entries_.find(utf8Path);
    if (it == entries_.end()) return nullptr;
    if (it->second.sources != sourceScope) return nullptr;
    return &it->second;
}

void HashCache::put(std::string utf8Path, CacheEntry entry) {
    entries_[std::move(utf8Path)] = std::move(entry);
}

} // namespace feather::cli
