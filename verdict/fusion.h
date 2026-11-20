#pragma once

#include <algorithm>
#include <vector>

#include "verdict/signal.h"

namespace feather {

// Aggregation rule: the verdict is the strongest severity any source reported.
// There is deliberately no numeric threshold -- see docs/VERDICT-MODEL.md.
inline Severity fuseSignals(const std::vector<Signal>& signals) {
    Severity verdict = Severity::None;
    for (const auto& signal : signals) {
        verdict = std::max(verdict, signal.severity);
    }
    return verdict;
}

} // namespace feather
