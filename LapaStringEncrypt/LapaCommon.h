#pragma once

#include <cstdint>
#include <cstddef>
#include <array>
#include <string>
#include <windows.h>

namespace LapaCrypto {
namespace Detail {

    inline void SecureWipeMemory(void* ptr, size_t size) noexcept {
        if (ptr && size > 0) {
            SecureZeroMemory(ptr, size);
        }
    }

    constexpr uint8_t RotL8(uint8_t val, unsigned int count) noexcept {
        unsigned int c = count & 7;
        if (c == 0) return val;
        return static_cast<uint8_t>((val << c) | (val >> (8 - c)));
    }

    constexpr uint8_t RotR8(uint8_t val, unsigned int count) noexcept {
        unsigned int c = count & 7;
        if (c == 0) return val;
        return static_cast<uint8_t>((val >> c) | (val << (8 - c)));
    }

    constexpr uint64_t MakeCompileTimeSeed(uint64_t counter) noexcept {
        uint64_t h = (counter * 0x14057b7ef767814fULL) ^ 0xcbf29ce484222325ULL;
        h = (h ^ (h >> 30)) * 0xbf58476d1ce4e5b9ULL;
        h = (h ^ (h >> 27)) * 0x94d049bb133111ebULL;
        return h ^ (h >> 31);
    }

    constexpr uint64_t StepPRNG(uint64_t state) noexcept {
        state ^= (state << 13);
        state ^= (state >> 7);
        state ^= (state << 17);
        return state + 0x9E3779B97F4A7C15ULL;
    }

    constexpr uint32_t Fnv1aHash(const uint8_t* data, size_t size) noexcept {
        uint32_t hash = 0x811c9dc5;
        for (size_t i = 0; i < size; ++i) {
            hash ^= data[i];
            hash *= 0x01000193;
        }
        return hash;
    }

} // namespace Detail
} // namespace LapaCrypto

namespace LapaStringEncrypt = LapaCrypto;
