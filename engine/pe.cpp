#include "engine/pe.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <string_view>

namespace feather {
namespace {

struct View {
    const std::uint8_t* d = nullptr;
    std::size_t n = 0;

    bool has(std::size_t off, std::size_t len) const {
        return off <= n && len <= n - off;
    }
    std::uint16_t u16(std::size_t off) const {
        if (!has(off, 2)) return 0;
        return static_cast<std::uint16_t>(d[off] | (d[off + 1] << 8));
    }
    std::uint32_t u32(std::size_t off) const {
        if (!has(off, 4)) return 0;
        return static_cast<std::uint32_t>(d[off]) |
               (static_cast<std::uint32_t>(d[off + 1]) << 8) |
               (static_cast<std::uint32_t>(d[off + 2]) << 16) |
               (static_cast<std::uint32_t>(d[off + 3]) << 24);
    }
    // Reads a NUL-terminated printable ASCII string, bounded.
    std::string asciiz(std::size_t off, std::size_t maxLen) const {
        std::string out;
        if (off >= n) return out;
        const std::size_t end = std::min(n, off + maxLen);
        for (std::size_t i = off; i < end; ++i) {
            const std::uint8_t c = d[i];
            if (c == 0) break;
            if (c < 0x20 || c > 0x7e) return {}; // not a sane name
            out.push_back(static_cast<char>(c));
        }
        return out;
    }
};

double entropyOf(const View& v, std::size_t off, std::size_t len) {
    if (len == 0 || !v.has(off, len)) return 0.0;
    std::array<std::uint64_t, 256> counts{};
    for (std::size_t i = 0; i < len; ++i) counts[v.d[off + i]]++;
    double h = 0.0;
    const double total = static_cast<double>(len);
    for (std::uint64_t c : counts) {
        if (c == 0) continue;
        const double p = static_cast<double>(c) / total;
        h -= p * std::log2(p);
    }
    return h;
}

std::string lower(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

struct DataDir {
    std::uint32_t rva = 0;
    std::uint32_t size = 0;
};

} // namespace

PeInfo parsePe(const std::uint8_t* data, std::size_t size) {
    PeInfo info;
    View v{data, size};

    if (size < 0x40 || v.u16(0) != 0x5A4D) return info; // 'MZ'

    const std::uint32_t peOff = v.u32(0x3C);
    if (!v.has(peOff, 24) || v.u32(peOff) != 0x00004550u) return info; // 'PE\0\0'

    const std::uint16_t machine = v.u16(peOff + 4);
    const std::uint16_t numSections = v.u16(peOff + 6);
    const std::uint16_t optSize = v.u16(peOff + 20);
    const std::size_t optOff = static_cast<std::size_t>(peOff) + 24;

    if (!v.has(optOff, optSize) || optSize < 64) return info;

    const std::uint16_t magic = v.u16(optOff);
    if (magic != 0x10B && magic != 0x20B) return info;

    info.valid = true;
    info.is64 = (magic == 0x20B);
    info.machine = machine;
    info.timestamp = v.u32(peOff + 8);
    info.imageSize = v.u32(optOff + 56);

    const std::size_t ddOff = optOff + (info.is64 ? 112 : 96);
    const std::uint32_t numDirs = v.u32(optOff + (info.is64 ? 108 : 92));
    const std::uint32_t maxDirs = std::min<std::uint32_t>(numDirs, 16);

    auto dataDir = [&](std::uint32_t index) -> DataDir {
        if (index >= maxDirs) return {};
        const std::size_t off = ddOff + index * 8u;
        return {v.u32(off), v.u32(off + 4)};
    };

    const DataDir secDir = dataDir(4);
    info.hasSignature = secDir.rva != 0 && secDir.size != 0;
    info.signatureSize = secDir.size;

    // ---- sections ---------------------------------------------------------
    const std::size_t secStart = optOff + optSize;
    if (numSections > 96) return info; // absurd header, stop here

    std::uint64_t maxRawEnd = 0;
    for (std::uint16_t i = 0; i < numSections; ++i) {
        const std::size_t off = secStart + std::size_t(i) * 40;
        if (!v.has(off, 40)) break;

        PeSection s;
        char name[9] = {};
        std::memcpy(name, data + off, 8);
        s.name = lower(std::string(name, std::strlen(name)));
        s.virtualSize = v.u32(off + 8);
        s.virtualAddress = v.u32(off + 12);
        s.rawSize = v.u32(off + 16);
        s.rawOffset = v.u32(off + 20);
        s.characteristics = v.u32(off + 36);

        const std::size_t sample = std::min<std::size_t>(s.rawSize, 1u << 20);
        s.entropy = entropyOf(v, s.rawOffset, sample);

        if (s.executable() && s.entropy > info.maxExecutableEntropy) {
            info.maxExecutableEntropy = s.entropy;
        }
        if (s.executable() && s.writable()) {
            info.hasWritableExecutableSection = true;
        }
        if (s.rawSize > 0) {
            maxRawEnd = std::max<std::uint64_t>(
                maxRawEnd, std::uint64_t(s.rawOffset) + s.rawSize);
        }
        info.sections.push_back(std::move(s));
    }

    if (maxRawEnd > 0 && maxRawEnd < size) {
        info.overlaySize = static_cast<std::uint32_t>(size - maxRawEnd);
    }

    // ---- rva -> file offset ----------------------------------------------
    auto mapRva = [&](std::uint32_t rva, std::uint32_t rvaSpan,
                      std::size_t want, std::size_t& out) -> bool {
        (void)rvaSpan;
        for (const auto& s : info.sections) {
            const std::uint32_t span = std::max(s.virtualSize, s.rawSize);
            if (rva < s.virtualAddress || rva - s.virtualAddress >= span) continue;

            const std::uint64_t delta = rva - s.virtualAddress;
            if (delta + want > s.rawSize) return false;  // zero-filled tail
            const std::uint64_t off = std::uint64_t(s.rawOffset) + delta;
            out = static_cast<std::size_t>(off);
            return v.has(out, want);
        }
        return false;
    };

    // ---- imports ----------------------------------------------------------
    const DataDir impDir = dataDir(1);
    if (impDir.rva != 0) {
        std::size_t descOff = 0;
        if (mapRva(impDir.rva, impDir.size, 20, descOff)) {
            std::size_t totalFuncs = 0;
            for (std::uint32_t i = 0; i < 512 && totalFuncs < 4096; ++i) {
                const std::size_t off = descOff + std::size_t(i) * 20;
                if (!v.has(off, 20)) break;
                const std::uint32_t oft = v.u32(off);
                const std::uint32_t nameRva = v.u32(off + 12);
                const std::uint32_t ft = v.u32(off + 16);
                if (oft == 0 && nameRva == 0 && ft == 0) break;

                std::size_t nameOff = 0;
                std::string mod;
                if (nameRva != 0 && mapRva(nameRva, 0, 1, nameOff)) {
                    mod = lower(v.asciiz(nameOff, 256));
                }
                if (mod.empty()) continue;
                info.importedModules.push_back(mod);

                const std::uint32_t thunkRva = oft != 0 ? oft : ft;
                std::size_t thunkOff = 0;
                const std::size_t entry = info.is64 ? 8 : 4;
                if (thunkRva != 0 && mapRva(thunkRva, 0, entry, thunkOff)) {
                    for (std::uint32_t t = 0; t < 128 && totalFuncs < 4096; ++t) {
                        const std::size_t toff = thunkOff + std::size_t(t) * entry;
                        if (!v.has(toff, entry)) break;
                        std::uint64_t val = info.is64
                            ? (std::uint64_t(v.u32(toff)) | (std::uint64_t(v.u32(toff + 4)) << 32))
                            : std::uint64_t(v.u32(toff));
                        if (val == 0) break;
                        const std::uint64_t highBit =
                            info.is64 ? (1ull << 63) : (1ull << 31);
                        if ((val & highBit) != 0) {
                            info.importedFunctions.push_back(
                                mod + "!#" + std::to_string(val & 0xffff));
                            ++totalFuncs;
                            continue;
                        }
                        const std::uint32_t nameRva2 = static_cast<std::uint32_t>(val & 0x7fffffff);
                        std::size_t fnOff = 0;
                        if (mapRva(nameRva2, 0, 2, fnOff)) {
                            const std::string fn = v.asciiz(fnOff + 2, 256);
                            if (!fn.empty()) {
                                info.importedFunctions.push_back(mod + "!" + lower(fn));
                                ++totalFuncs;
                            }
                        }
                    }
                }
            }
        }
    }

    // ---- exports (bounded sample) ----------------------------------------
    const DataDir expDir = dataDir(0);
    if (expDir.rva != 0) {
        std::size_t expOff = 0;
        if (mapRva(expDir.rva, expDir.size, 40, expOff)) {
            std::uint32_t ordinalBase = v.u32(expOff + 16);
            std::uint32_t numNames = v.u32(expOff + 24);
            std::uint32_t namesRva = v.u32(expOff + 32);
            std::size_t namesOff = 0;
            if (numNames <= 512 && namesRva != 0 &&
                mapRva(namesRva, 0, 4, namesOff)) {
                for (std::uint32_t i = 0; i < numNames && i < 512; ++i) {
                    std::size_t entryOff = namesOff + std::size_t(i) * 4;
                    if (!v.has(entryOff, 4)) break;
                    std::size_t nameOff = 0;
                    if (mapRva(v.u32(entryOff), 0, 1, nameOff)) {
                        std::string name = v.asciiz(nameOff, 256);
                        if (!name.empty()) info.exports.push_back(std::move(name));
                    }
                }
            }
            (void)ordinalBase;
        }
    }

    info.hasNoImports = info.importedModules.empty();
    return info;
}

} // namespace feather
