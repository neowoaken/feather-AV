#include "cli/quarantine.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#endif

#include "engine/sha256.h"

namespace fs = std::filesystem;

namespace feather::cli {
namespace {

std::string toUtf8(const fs::path& p) {
    const std::u8string u8 = p.u8string();
    return std::string(reinterpret_cast<const char*>(u8.data()), u8.size());
}

std::string nowStamp() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    char buf[32] = {};
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm);
    return buf;
}

bool isHex64(const std::string& s) {
    if (s.size() != 64) return false;
    for (char c : s) {
        const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                        (c >= 'A' && c <= 'F');
        if (!ok) return false;
    }
    return true;
}

std::string lower(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'F') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

bool hashFile(const fs::path& path, std::string& hex, std::string& error) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        error = "cannot open for verification: " + toUtf8(path);
        return false;
    }

    std::vector<char> buf(1u << 20);
    Sha256 hasher;
    while (in) {
        in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
        const std::streamsize got = in.gcount();
        if (got > 0) hasher.update(buf.data(), static_cast<std::size_t>(got));
    }
    hex = Sha256::hex(hasher.final());
    return true;
}

void appendLine(const fs::path& manifest, const std::string& line) {
    std::ofstream out(manifest, std::ios::app | std::ios::binary);
    out << line << '\n';
}

} // namespace

fs::path Quarantine::defaultRoot() {
#ifdef _WIN32
    wchar_t buf[MAX_PATH] = {};
    const DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", buf, MAX_PATH);
    if (n > 0 && n < MAX_PATH) {
        return fs::path(std::wstring(buf, n)) / L"Feather" / L"quarantine";
    }
#endif
    if (const char* home = std::getenv("HOME")) {
        return fs::path(home) / ".local" / "share" / "feather" / "quarantine";
    }
    return fs::path("feather-quarantine");
}

fs::path Quarantine::systemRoot() {
#ifdef _WIN32
    wchar_t buf[MAX_PATH] = {};
    const DWORD n = GetEnvironmentVariableW(L"PROGRAMDATA", buf, MAX_PATH);
    if (n > 0 && n < MAX_PATH) {
        return fs::path(std::wstring(buf, n)) / L"Feather" / L"quarantine";
    }
#endif
    return defaultRoot();
}

Quarantine::Quarantine(fs::path root) : root_(std::move(root)) {}

fs::path Quarantine::manifestPath() const { return root_ / "manifest.tsv"; }

fs::path Quarantine::objectPath(const std::string& sha256Hex) const {
    return root_ / "objects" / (sha256Hex + ".q");
}

bool Quarantine::add(const fs::path& file, const std::string& sha256Hex,
                     const std::string& categoryId, const std::string& reason,
                     std::string& error) {
    if (!isHex64(sha256Hex)) {
        error = "invalid sha256";
        return false;
    }

    const std::string key = lower(sha256Hex);
    std::error_code ec;
    if (!fs::is_regular_file(file, ec)) {
        error = "not a regular file: " + toUtf8(file);
        return false;
    }

    fs::create_directories(root_ / "objects", ec);
    if (ec) {
        error = "cannot create quarantine directory: " + ec.message();
        return false;
    }

    const fs::path target = objectPath(key);
    if (fs::exists(target, ec)) {
        error = "already quarantined: " + toUtf8(target);
        return false;
    }

    const std::uint64_t size = fs::file_size(file, ec);
    if (ec) {
        error = "cannot stat file: " + ec.message();
        return false;
    }

    // Copy first, verify the copy, and only then remove the original. A failed
    // copy must never destroy the user's file.
    fs::copy_file(file, target, fs::copy_options::none, ec);
    if (ec) {
        error = "copy failed: " + ec.message();
        return false;
    }

    std::string storedHash;
    std::string verifyError;
    if (!hashFile(target, storedHash, verifyError) || storedHash != key) {
        fs::remove(target, ec);
        error = "verification failed, original left untouched: " +
                (verifyError.empty() ? "hash mismatch" : verifyError);
        return false;
    }

    fs::remove(file, ec);
    if (ec) {
        fs::remove(target, ec);
        error = "could not remove original: " + ec.message();
        return false;
    }

    std::ostringstream line;
    line << nowStamp() << '\t' << key << '\t' << categoryId << '\t' << size
         << '\t' << toUtf8(file);
    if (!reason.empty()) {
        line << '\t' << reason;
    }
    appendLine(manifestPath(), line.str());
    return true;
}

std::vector<QuarantineEntry> Quarantine::list(std::string& error) const {
    std::vector<QuarantineEntry> entries;

    std::ifstream in(manifestPath());
    if (!in) return entries;  // empty quarantine is not an error

    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;

        std::vector<std::string> fields;
        std::size_t start = 0;
        for (int i = 0; i < 5; ++i) {
            const std::size_t tab = line.find('\t', start);
            if (tab == std::string::npos) {
                fields.push_back(line.substr(start));
                start = std::string::npos;
                break;
            }
            fields.push_back(line.substr(start, tab - start));
            start = tab + 1;
        }

        if (fields.size() < 5) {
            error = "manifest: skipping malformed line";
            continue;
        }

        QuarantineEntry entry;
        entry.timestamp = fields[0];
        entry.sha256 = fields[1];
        entry.category = fields[2];
        try {
            entry.size = std::stoull(fields[3]);
        } catch (...) {
            entry.size = 0;
        }
        entry.originalPath = fields[4];
        entries.push_back(std::move(entry));
    }
    return entries;
}

bool Quarantine::restore(const std::string& sha256Hex, fs::path& restoredTo,
                         std::string& error) {
    if (!isHex64(sha256Hex)) {
        error = "invalid sha256";
        return false;
    }
    const std::string key = lower(sha256Hex);

    std::string listError;
    const auto entries = list(listError);
    const QuarantineEntry* found = nullptr;
    for (const auto& entry : entries) {
        if (entry.sha256 == key) {
            found = &entry;
            break;
        }
    }
    if (found == nullptr) {
        error = "not in quarantine: " + key;
        return false;
    }

    const fs::path source = objectPath(key);
    const fs::path destination = fs::path(found->originalPath);

    std::error_code ec;
    if (!fs::exists(source, ec)) {
        error = "quarantine object missing: " + toUtf8(source);
        return false;
    }
    if (fs::exists(destination, ec)) {
        error = "original path already exists: " + toUtf8(destination);
        return false;
    }

    if (destination.has_parent_path()) {
        fs::create_directories(destination.parent_path(), ec);
    }

    fs::rename(source, destination, ec);
    if (ec) {
        // Cross-volume restore.
        ec.clear();
        fs::copy_file(source, destination, fs::copy_options::none, ec);
        if (ec) {
            error = "restore failed: " + ec.message();
            return false;
        }
        fs::remove(source, ec);
    }

    // Drop the entry from the manifest.
    const fs::path tmp = manifestPath().string() + ".tmp";
    {
        std::ifstream in(manifestPath());
        std::ofstream out(tmp, std::ios::trunc);
        std::string line;
        while (std::getline(in, line)) {
            if (line.size() > 65) {
                const std::size_t t1 = line.find('\t');
                if (t1 != std::string::npos) {
                    const std::size_t t2 = line.find('\t', t1 + 1);
                    if (t2 != std::string::npos &&
                        line.substr(t1 + 1, t2 - t1 - 1) == key) {
                        continue;
                    }
                }
            }
            out << line << '\n';
        }
    }
    fs::remove(manifestPath(), ec);
    fs::rename(tmp, manifestPath(), ec);

    restoredTo = destination;
    return true;
}

} // namespace feather::cli
