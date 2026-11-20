#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "engine/exclusions.h"
#include "engine/ioc.h"
#include "engine/pe.h"
#include "sources/clamav_source.h"
#include "sources/source.h"
#include "verdict/signal.h"

namespace feather {

struct RuleHit {
    std::string source;  // which source produced this signal
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

    // Sources that failed for this file. Non-fatal: other sources still ran.
    std::vector<std::string> warnings;

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

struct EngineConfig {
    IocDatabase ioc;
    Exclusions exclusions;
    std::optional<ClamAvEndpoint> clamd;  // nullopt = ClamAV disabled
    EngineOptions options{};
};

// Orchestrator: hashes once, parses PE once, feeds the facts to every
// configured source, then fuses the signals into a single verdict.
class Engine {
public:
    explicit Engine(EngineConfig config = {});

    Finding analyze(const std::filesystem::path& path) const;

    // Applies user exclusions to an already-analysed finding. Exposed so the
    // CLI can re-apply them to cache hits without re-reading the file.
    void applyExclusions(Finding& finding) const;

    // Identifies the active source set ("rules+ioc", "rules+ioc+clamav@host:port").
    // Cached verdicts are only valid for the same source set: a file cached
    // before ClamAV was enabled must not skip ClamAV afterwards.
    const std::string& sourceScope() const { return scope_; }

    const EngineOptions& options() const { return options_; }

private:
    EngineConfig config_;
    std::vector<std::unique_ptr<SignalSource>> sources_;
    Exclusions exclusions_;
    EngineOptions options_{};
    std::string scope_;
};

} // namespace feather
