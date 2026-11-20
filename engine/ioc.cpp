#include "engine/ioc.h"

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

IocDatabase IocDatabase::loadFromFile(const std::filesystem::path& path,
                                      std::string& error) {
    IocDatabase db;

    std::ifstream in(path);
    if (!in) {
        error = "cannot open IOC file: " + path.string();
        return db;
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
        if (kind != "sha256" || !isHexHash(value)) {
            error = "line " + std::to_string(lineNo) +
                    ": expected 'sha256 <64 hex chars> [label]'";
            continue;
        }

        std::string label;
        std::getline(ss, label);
        label = trim(label);

        for (char& c : value) {
            if (c >= 'A' && c <= 'F') c = static_cast<char>(c - 'A' + 'a');
        }

        IocEntry entry;
        entry.label = label;
        db.entries_[value] = std::move(entry);
    }
    return db;
}

const IocEntry* IocDatabase::find(const Digest& digest) const {
    const std::string key = Sha256::hex(digest);
    const auto it = entries_.find(key);
    return it == entries_.end() ? nullptr : &it->second;
}

} // namespace feather
