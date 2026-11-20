#pragma once

#include "engine/ioc.h"
#include "sources/source.h"

namespace feather {

// Known-bad hash lookup. Hash-only by design: no filename or pattern entries.
class IocSource final : public SignalSource {
public:
    explicit IocSource(const IocDatabase* database) : database_(database) {}

    const char* name() const override { return "ioc"; }
    SourceResult inspect(const FileFacts& facts) const override;

private:
    const IocDatabase* database_;
};

} // namespace feather
