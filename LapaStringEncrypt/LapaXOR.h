#pragma once

#include "LapaCommon.h"

namespace LapaCrypto {
namespace Detail {

    template <size_t Size, uint64_t Seed>
    constexpr std::array<uint8_t, Size> EncryptARXXor(const std::array<char, Size>& input) noexcept {
        std::array<uint8_t, Size> buf{};
        for (size_t i = 0; i < Size; ++i) {
            buf[i] = static_cast<uint8_t>(input[i]);
        }

        uint64_t state = Seed ^ 0x3C6EF372FE94F82BULL;
        uint8_t prev = static_cast<uint8_t>(Seed & 0xFF);

        for (size_t i = 0; i < Size; ++i) {
            state = StepPRNG(state);
            uint8_t k = static_cast<uint8_t>(state & 0xFF);
            uint8_t rot = static_cast<uint8_t>((i % 5) + 1);
            uint8_t shift = static_cast<uint8_t>((i * 29 + 17) & 0xFF);

            uint8_t b = buf[i] ^ k;
            b = RotL8(b, rot);
            b = static_cast<uint8_t>((b + shift) & 0xFF);
            b ^= prev;

            buf[i] = b;
            prev = b;
        }

        for (size_t i = Size; i > 0; --i) {
            size_t idx = i - 1;
            state = StepPRNG(state);
            uint8_t k = static_cast<uint8_t>((state >> 8) & 0xFF);
            uint8_t rot = static_cast<uint8_t>((idx % 3) + 1);

            uint8_t b = buf[idx] ^ k;
            b = RotR8(b, rot);
            b = static_cast<uint8_t>((b - 0x3C) & 0xFF);
            buf[idx] = b;
        }

        return buf;
    }

    template <size_t Size>
    inline void DecryptARXXor(const uint8_t* in, char* out, uint64_t seed) noexcept {
        uint8_t roundKeys1[Size];
        uint8_t roundKeys2[Size];
        uint8_t work[Size];

        uint64_t state = seed ^ 0x3C6EF372FE94F82BULL;
        for (size_t i = 0; i < Size; ++i) {
            state = StepPRNG(state);
            roundKeys1[i] = static_cast<uint8_t>(state & 0xFF);
        }
        for (size_t i = Size; i > 0; --i) {
            size_t idx = i - 1;
            state = StepPRNG(state);
            roundKeys2[idx] = static_cast<uint8_t>((state >> 8) & 0xFF);
        }

        for (size_t i = 0; i < Size; ++i) {
            work[i] = in[i];
        }

        for (size_t idx = 0; idx < Size; ++idx) {
            uint8_t rot = static_cast<uint8_t>((idx % 3) + 1);
            uint8_t k = roundKeys2[idx];

            uint8_t b = work[idx];
            b = static_cast<uint8_t>((b + 0x3C) & 0xFF);
            b = RotL8(b, rot);
            b ^= k;
            work[idx] = b;
        }

        for (size_t idx = Size; idx > 0; --idx) {
            size_t i = idx - 1;
            uint8_t prev = (i > 0) ? work[i - 1] : static_cast<uint8_t>(seed & 0xFF);
            uint8_t rot = static_cast<uint8_t>((i % 5) + 1);
            uint8_t shift = static_cast<uint8_t>((i * 29 + 17) & 0xFF);
            uint8_t k = roundKeys1[i];

            uint8_t b = work[i];
            b ^= prev;
            b = static_cast<uint8_t>((b - shift) & 0xFF);
            b = RotR8(b, rot);
            b ^= k;
            work[i] = b;
        }

        for (size_t i = 0; i < Size; ++i) {
            out[i] = static_cast<char>(work[i]);
        }

        SecureWipeMemory(roundKeys1, sizeof(roundKeys1));
        SecureWipeMemory(roundKeys2, sizeof(roundKeys2));
        SecureWipeMemory(work, sizeof(work));
    }

} // namespace Detail
} // namespace LapaCrypto
