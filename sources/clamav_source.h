#pragma once

#include <cstdint>
#include <string>

#include "sources/source.h"

namespace feather {

struct ClamAvEndpoint {
    std::string host = "127.0.0.1";
    std::uint16_t port = 3310;
};

// Adapter for a local clamd daemon (ClamAV). Speaks the documented INSTREAM
// protocol over a socket instead of linking libclamav, which keeps feather's
// licence boundary clean: ClamAV is GPL-2.0, this adapter is MIT, and they are
// separate programs. ClamAV is never bundled.
//
// The adapter is also a classifier: ClamAV's PUA/HackTool/Heuristic verdicts
// are downgraded to `unwanted`, because "this is a game fix" is not proof of
// malice.
class ClamAvSource final : public SignalSource {
public:
    explicit ClamAvSource(ClamAvEndpoint endpoint);

    const char* name() const override { return "clamav"; }
    SourceResult inspect(const FileFacts& facts) const override;

private:
    ClamAvEndpoint endpoint_;
};

struct ClamClassification {
    Severity severity = Severity::Malicious;
    Category category = Category::Malware;
};

// Maps a ClamAV signature name to a tier and a category. Exposed for tests.
ClamClassification classifyClamSignature(const std::string& signature);

} // namespace feather
