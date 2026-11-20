// feather -- self-contained SHA-256 (no OpenSSL / CNG dependency, keeps the
// engine portable so CI can run it on Linux too).
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace feather {

using Digest = std::array<std::uint8_t, 32>;

class Sha256 {
public:
    Sha256();

    void update(const void* data, std::size_t len);
    Digest final();

    static Digest hash(std::span<const std::uint8_t> data);
    static std::string hex(const Digest& digest);

private:
    void reset();
    void block(const std::uint8_t* p);

    std::uint32_t h_[8];
    std::uint8_t buf_[64];
    std::size_t bufLen_;
    std::uint64_t total_;
};

} // namespace feather
