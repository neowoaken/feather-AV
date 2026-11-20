#include "engine/engine.h"

#include <algorithm>
#include <fstream>

#include "sources/ioc_source.h"
#include "sources/rules_source.h"
#include "verdict/fusion.h"

namespace feather {

Engine::Engine(EngineConfig config)
    : config_(std::move(config)),
      exclusions_(config_.exclusions),
      options_(config_.options) {
    sources_.push_back(std::make_unique<RulesSource>());
    sources_.push_back(std::make_unique<IocSource>(&config_.ioc));
    scope_ = "rules+ioc";

    if (config_.clamd) {
        sources_.push_back(std::make_unique<ClamAvSource>(*config_.clamd));
        scope_ += "+clamav@" + config_.clamd->host + ":" +
                  std::to_string(config_.clamd->port);
    }
}

void Engine::applyExclusions(Finding& finding) const {
    if (finding.verdict == Severity::Malicious) return;

    const std::u8string u8 = finding.path.u8string();
    const std::string utf8Path(reinterpret_cast<const char*>(u8.data()),
                               u8.size());
    const std::string reason = exclusions_.match(finding.digest, utf8Path);
    if (!reason.empty()) {
        finding.suppressed = true;
        finding.suppressionReason = reason;
    }
}

Finding Engine::analyze(const std::filesystem::path& path) const {
    Finding f;
    f.path = path;

    std::error_code ec;
    const auto sizeOpt = std::filesystem::file_size(path, ec);
    if (ec) {
        f.error = "cannot stat: " + ec.message();
        return f;
    }
    f.size = static_cast<std::uint64_t>(sizeOpt);

    // ---- hash the whole file (streamed) -----------------------------------
    {
        std::ifstream in(path, std::ios::binary);
        if (!in) {
            f.error = "cannot open for reading (locked or access denied)";
            return f;
        }

        std::vector<char> buf(1u << 20);
        Sha256 hasher;
        while (in) {
            in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
            const std::streamsize got = in.gcount();
            if (got > 0) hasher.update(buf.data(), static_cast<std::size_t>(got));
        }
        f.digest = hasher.final();
        f.sha256 = Sha256::hex(f.digest);
    }

    // ---- PE structure (prefix read) ---------------------------------------
    {
        std::ifstream in(path, std::ios::binary);
        if (in) {
            const std::uint64_t want =
                std::min<std::uint64_t>(f.size, options_.peReadLimit);
            std::vector<std::uint8_t> head(static_cast<std::size_t>(want));
            if (want > 0) {
                in.read(reinterpret_cast<char*>(head.data()),
                        static_cast<std::streamsize>(want));
                head.resize(static_cast<std::size_t>(in.gcount()));
            }
            f.pe = parsePe(head.data(), head.size());
        }
    }

    // ---- run every source --------------------------------------------------
    const FileFacts facts{path, f.size, f.digest, f.sha256, f.pe};

    std::vector<Signal> signals;
    for (const auto& source : sources_) {
        SourceResult result = source->inspect(facts);
        if (!result.error.empty()) {
            f.warnings.push_back(std::string(source->name()) + ": " + result.error);
        }
        for (auto& signal : result.signals) {
            signal.source = source->name();
            signals.push_back(std::move(signal));
        }
    }

    // ---- fuse ---------------------------------------------------------------
    f.verdict = fuseSignals(signals);
    f.hits.reserve(signals.size());
    for (const auto& signal : signals) {
        f.hits.push_back(RuleHit{signal.source, signal.id, signal.severity,
                                 signal.category, signal.weight, signal.detail});
        if (signal.severity == f.verdict && f.category == Category::None) {
            f.category = signal.category;
        }
    }

    // ---- user exclusions ----------------------------------------------------
    applyExclusions(f);

    return f;
}

} // namespace feather
