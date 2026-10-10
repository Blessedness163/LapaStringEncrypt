#pragma once

#include "LapaCommon.h"

namespace LapaCrypto {
namespace Detail {

    constexpr size_t Base64EncodedSize(size_t inSize) noexcept {
        return ((inSize + 2) / 3) * 4;
    }

    constexpr std::array<char, 64> GenerateShuffledAlphabet(uint64_t seed) noexcept {
        const char baseTable[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::array<char, 64> alpha{};
        for (size_t i = 0; i < 64; ++i) {
            alpha[i] = baseTable[i];
        }

        uint64_t state = seed ^ 0xA5A5A5A55A5A5A5AULL;
        for (size_t i = 63; i > 0; --i) {
            state = StepPRNG(state);
            size_t j = static_cast<size_t>(state % (i + 1));
            char tmp = alpha[i];
            alpha[i] = alpha[j];
            alpha[j] = tmp;
        }

        return alpha;
    }

    template <size_t InSize, uint64_t Seed>
    constexpr std::array<char, Base64EncodedSize(InSize)> EncodeBase64(const uint8_t* in) noexcept {
        constexpr size_t OutSize = Base64EncodedSize(InSize);
        std::array<char, OutSize> out{};
        auto alpha = GenerateShuffledAlphabet(Seed);

        size_t outIdx = 0;
        size_t i = 0;
        while (i < InSize) {
            size_t remaining = InSize - i;
            uint32_t b0 = in[i++];
            uint32_t b1 = (remaining > 1) ? in[i++] : 0;
            uint32_t b2 = (remaining > 2) ? in[i++] : 0;

            uint32_t triple = (b0 << 16) | (b1 << 8) | b2;

            out[outIdx++] = alpha[(triple >> 18) & 0x3F];
            out[outIdx++] = alpha[(triple >> 12) & 0x3F];
            out[outIdx++] = (remaining > 1) ? alpha[(triple >> 6) & 0x3F] : '=';
            out[outIdx++] = (remaining > 2) ? alpha[triple & 0x3F] : '=';
        }

        return out;
    }

    inline bool DecodeBase64(const char* in, size_t inLen, uint8_t* out, size_t expectedOutLen, uint64_t seed) noexcept {
        auto alpha = GenerateShuffledAlphabet(seed);
        uint8_t invTable[256];
        for (int k = 0; k < 256; ++k) invTable[k] = 0xFF;
        for (uint8_t k = 0; k < 64; ++k) {
            invTable[static_cast<uint8_t>(alpha[k])] = k;
        }

        size_t inIdx = 0;
        size_t outIdx = 0;

        while (inIdx < inLen && outIdx < expectedOutLen) {
            char c0 = in[inIdx++];
            char c1 = (inIdx < inLen) ? in[inIdx++] : '=';
            char c2 = (inIdx < inLen) ? in[inIdx++] : '=';
            char c3 = (inIdx < inLen) ? in[inIdx++] : '=';

            uint8_t v0 = invTable[static_cast<uint8_t>(c0)];
            uint8_t v1 = invTable[static_cast<uint8_t>(c1)];
            uint8_t v2 = (c2 == '=') ? 0 : invTable[static_cast<uint8_t>(c2)];
            uint8_t v3 = (c3 == '=') ? 0 : invTable[static_cast<uint8_t>(c3)];

            uint32_t triple = (static_cast<uint32_t>(v0 & 0x3F) << 18) |
                              (static_cast<uint32_t>(v1 & 0x3F) << 12) |
                              (static_cast<uint32_t>(v2 & 0x3F) << 6)  |
                              static_cast<uint32_t>(v3 & 0x3F);

            if (outIdx < expectedOutLen) out[outIdx++] = static_cast<uint8_t>((triple >> 16) & 0xFF);
            if (c2 != '=' && outIdx < expectedOutLen) out[outIdx++] = static_cast<uint8_t>((triple >> 8) & 0xFF);
            if (c3 != '=' && outIdx < expectedOutLen) out[outIdx++] = static_cast<uint8_t>(triple & 0xFF);
        }

        SecureWipeMemory(invTable, sizeof(invTable));
        return outIdx == expectedOutLen;
    }

} // namespace Detail
} // namespace LapaCrypto
