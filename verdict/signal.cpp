#include "verdict/signal.h"

namespace feather {

const char* severityName(Severity severity) {
    switch (severity) {
        case Severity::Malicious: return "malicious";
        case Severity::Unwanted:  return "unwanted";
        case Severity::Info:      return "info";
        case Severity::None:
        default:                  return "clean";
    }
}

} // namespace feather
