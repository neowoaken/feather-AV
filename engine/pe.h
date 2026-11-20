// Minimal, bounds-checked PE parser. Deliberately does NOT decode resources,
// .NET metadata or authenticode contents -- just enough structure for the
// heuristics in engine.cpp.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace feather {

struct PeSection {
    std::string name;
    std::uint32_t virtualAddress = 0;
    std::uint32_t virtualSize = 0;
    std::uint32_t rawSize = 0;
    std::uint32_t rawOffset = 0;
    std::uint32_t characteristics = 0;
    double entropy = 0.0;

    bool executable() const { return (characteristics & 0x20000000u) != 0; }
    bool writable() const { return (characteristics & 0x80000000u) != 0; }
};

struct PeInfo {
    bool valid = false;
    bool is64 = false;
    std::uint16_t machine = 0;
    std::uint32_t timestamp = 0;
    std::uint32_t imageSize = 0;

    // Authenticode presence only. Absence is NOT a detection signal: most
    // game fixes / indie tools are unsigned.
    bool hasSignature = false;
    std::uint32_t signatureSize = 0;

    std::vector<PeSection> sections;
    std::vector<std::string> importedModules;    // lowercased module names
    std::vector<std::string> importedFunctions;  // "module!function", lowercased
    std::vector<std::string> exports;            // bounded sample

    double maxExecutableEntropy = 0.0;
    std::uint32_t overlaySize = 0;
    bool hasWritableExecutableSection = false;
    bool hasNoImports = false;
};

// `data` may be a prefix of the file; parsing degrades gracefully.
PeInfo parsePe(const std::uint8_t* data, std::size_t size);

} // namespace feather
