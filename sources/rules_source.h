#pragma once

#include "sources/source.h"

namespace feather {

// Built-in static heuristics. Same rules as v0.1, now expressed as one source
// among several instead of being hard-wired into the engine.
class RulesSource final : public SignalSource {
public:
    const char* name() const override { return "rules"; }
    SourceResult inspect(const FileFacts& facts) const override;
};

} // namespace feather
