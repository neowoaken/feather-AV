#include "sources/ioc_source.h"

namespace feather {

SourceResult IocSource::inspect(const FileFacts& facts) const {
    SourceResult result;
    if (database_ == nullptr) return result;

    if (const IocEntry* entry = database_->find(facts.digest)) {
        result.signals.push_back(
            Signal{"ioc", "hash.known_bad", Severity::Malicious, entry->category,
                   100,
                   entry->label.empty() ? "matches known-bad SHA-256"
                                        : ("known bad: " + entry->label)});
    }
    return result;
}

} // namespace feather
