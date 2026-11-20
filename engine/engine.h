#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "engine/exclusions.h"
#include "engine/ioc.h"
#include "engine/pe.h"
#include "engine/sha256.h"

namespace feather {

enum class Severity { None = 0, Info = 1, Unwanted = 2, Malicious = 3 };

const char* severityName(Severity severity);

struct RuleHit {
    std::string id;
    Severity severity = Severity::Info;
    int weight = 0;
    std::string detail;
};

struct Finding {
    std::filesystem::path path;
    std::uint64_t size = 0;
    Digest digest{};
    std::string sha256;

    Severity verdict = Severity::None;
    std::vector<RuleHit> hits;

    // Set when a user exclusion covered this file. Suppression is never
    // applied to a Malicious verdict; see exclusions.h.
    bool suppressed = false;
    std::string suppressionReason;

    // Result came from the hash cache instead of a fresh scan.
    bool cached = false;

    std::string error;
    PeInfo pe;

    Severity effectiveVerdict() const {
        return suppressed ? Severity::None : verdict;
    }
};

struct EngineOptions {
    // How much of a file to read for PE parsing. Hashing always streams the
    // whole file; this only bounds the in-memory header/section copy.
    std::size_t peReadLimit = 32u << 20;
};

class Engine {
public:
    Engine() = default;
    Engine(IocDatabase ioc, Exclusions exclusions, EngineOptions options = {});

    Finding analyze(const std::filesystem::path& path) const;

    const EngineOptions& options() const { return options_; }

private:
    IocDatabase ioc_;
    Exclusions exclusions_;
    EngineOptions options_{};
};

} // namespace feather
