#pragma once

#include "LapaCommon.h"

namespace LapaCrypto {
namespace Detail {

    template <size_t RawSize, uint64_t Seed>
    constexpr std::array<uint8_t, RawSize> TransformBytes(const uint8_t* in) noexcept {
        std::array<uint8_t, RawSize> out{};
        uint64_t r = Seed ^ 0x9e3779b97f4a7c15ULL;

        for (size_t i = 0; i < RawSize; ++i) {
            r = StepPRNG(r);
            uint8_t k1 = static_cast<uint8_t>(r & 0xFF);
            uint8_t k2 = static_cast<uint8_t>((r >> 8) & 0xFF);
            uint8_t rot = static_cast<uint8_t>((r >> 16) & 0x07);
            uint8_t indexShift = static_cast<uint8_t>((i * 37 + 11) & 0xFF);

            uint8_t b = in[i];
            b ^= k1;
            b = static_cast<uint8_t>((b + indexShift) & 0xFF);
            b = RotL8(b, rot);
            b = static_cast<uint8_t>((b * 13 + 7) & 0xFF);
            b ^= k2;

            out[i] = b;
        }

        return out;
    }

    template <size_t RawSize, uint64_t Seed>
    inline void UntransformBytes(const uint8_t* in, uint8_t* out) noexcept {
        uint64_t r = Seed ^ 0x9e3779b97f4a7c15ULL;

        for (size_t i = 0; i < RawSize; ++i) {
            r = StepPRNG(r);
            uint8_t k1 = static_cast<uint8_t>(r & 0xFF);
            uint8_t k2 = static_cast<uint8_t>((r >> 8) & 0xFF);
            uint8_t rot = static_cast<uint8_t>((r >> 16) & 0x07);
            uint8_t indexShift = static_cast<uint8_t>((i * 37 + 11) & 0xFF);

            uint8_t b = in[i];
            b ^= k2;
            b = static_cast<uint8_t>(((b - 7) * 197) & 0xFF);
            b = RotR8(b, rot);
            b = static_cast<uint8_t>((b - indexShift) & 0xFF);
            b ^= k1;

            out[i] = b;
        }
    }

} // namespace Detail
} // namespace LapaCrypto
