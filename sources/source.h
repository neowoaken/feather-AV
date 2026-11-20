#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "engine/pe.h"
#include "engine/sha256.h"
#include "verdict/signal.h"

namespace feather {

// Everything a source is allowed to know about a file. Hashing and PE parsing
// happen once, before any source runs.
struct FileFacts {
    std::filesystem::path path;
    std::uint64_t size = 0;
    Digest digest{};
    std::string sha256;
    const PeInfo& pe;
};

struct SourceResult {
    std::vector<Signal> signals;
    std::string error;  // non-fatal: the other sources still run
};

// A detection source is an adapter. It gets facts, it returns signals. It never
// decides a verdict, never deletes anything, and never talks to the user.
class SignalSource {
public:
    virtual ~SignalSource() = default;

    virtual const char* name() const = 0;
    virtual SourceResult inspect(const FileFacts& facts) const = 0;
};

} // namespace feather
