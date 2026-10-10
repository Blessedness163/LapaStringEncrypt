#pragma once

#include "LapaCommon.h"

namespace LapaCrypto {
namespace Detail {

    constexpr uint8_t GetCaesarBaseShift(uint64_t seed) noexcept {
        uint8_t shift = static_cast<uint8_t>((seed ^ (seed >> 16)) & 0xFF);
        return shift ? shift : 0x37;
    }

    constexpr uint8_t GetCaesarStep(uint64_t seed) noexcept {
        return static_cast<uint8_t>(((seed >> 8) | 1) & 0x1F);
    }

    template <size_t Size, uint64_t Seed>
    constexpr std::array<uint8_t, Size> EncryptCaesar(const uint8_t* in) noexcept {
        std::array<uint8_t, Size> out{};
        uint8_t baseShift = GetCaesarBaseShift(Seed);
        uint8_t step = GetCaesarStep(Seed);

        for (size_t i = 0; i < Size; ++i) {
            uint8_t shift = static_cast<uint8_t>((baseShift + i * step) & 0xFF);
            out[i] = static_cast<uint8_t>((in[i] + shift) & 0xFF);
        }

        return out;
    }

    template <size_t Size, uint64_t Seed>
    inline void DecryptCaesar(const uint8_t* in, uint8_t* out) noexcept {
        uint8_t baseShift = GetCaesarBaseShift(Seed);
        uint8_t step = GetCaesarStep(Seed);

        for (size_t i = 0; i < Size; ++i) {
            uint8_t shift = static_cast<uint8_t>((baseShift + i * step) & 0xFF);
            out[i] = static_cast<uint8_t>((in[i] - shift) & 0xFF);
        }
    }

} // namespace Detail
} // namespace LapaCrypto
