#pragma once

#include <windows.h>
#include <bcrypt.h>
#include <cstdint>
#include <vector>
#include <string>
#include <stdexcept>

#pragma comment(lib, "bcrypt.lib")

namespace LapaCrypto {
namespace Hash {

    namespace Detail {
        struct ScopedAlg {
            BCRYPT_ALG_HANDLE handle = NULL;
            ~ScopedAlg() { if (handle) BCryptCloseAlgorithmProvider(handle, 0); }
            operator BCRYPT_ALG_HANDLE() const noexcept { return handle; }
            BCRYPT_ALG_HANDLE* operator&() noexcept { return &handle; }
        };

        struct ScopedHash {
            BCRYPT_HASH_HANDLE handle = NULL;
            ~ScopedHash() { if (handle) BCryptDestroyHash(handle); }
            operator BCRYPT_HASH_HANDLE() const noexcept { return handle; }
            BCRYPT_HASH_HANDLE* operator&() noexcept { return &handle; }
        };
    }

    inline std::vector<uint8_t> ComputeSHA256(const std::string& input) {
        Detail::ScopedAlg alg;
        Detail::ScopedHash hashHandle;
        std::vector<uint8_t> hash(32);

        NTSTATUS status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
        if (status < 0) throw std::runtime_error("BCryptOpenAlgorithmProvider failed");

        status = BCryptCreateHash(alg, &hashHandle, NULL, 0, NULL, 0, 0);
        if (status >= 0) {
            status = BCryptHashData(
                hashHandle, 
                (PUCHAR)input.data(), 
                static_cast<ULONG>(input.size()), 
                0
            );
            if (status >= 0) {
                status = BCryptFinishHash(hashHandle, hash.data(), static_cast<ULONG>(hash.size()), 0);
            }
        }

        if (status < 0) {
            throw std::runtime_error("ComputeSHA256 failed");
        }

        return hash;
    }

    inline std::string ComputeSHA256Hex(const std::string& input) {
        auto hash = ComputeSHA256(input);
        static const char hexChars[] = "0123456789abcdef";
        std::string hex;
        hex.reserve(64);
        for (uint8_t b : hash) {
            hex.push_back(hexChars[(b >> 4) & 0x0F]);
            hex.push_back(hexChars[b & 0x0F]);
        }
        return hex;
    }

    inline std::vector<uint8_t> DeriveKeyPBKDF2(
        const std::string& password,
        const std::string& salt,
        unsigned int iterations = 100000,
        size_t keyLength = 32
    ) {
        Detail::ScopedAlg alg;
        std::vector<uint8_t> derivedKey(keyLength);

        NTSTATUS status = BCryptOpenAlgorithmProvider(
            &alg, 
            BCRYPT_SHA256_ALGORITHM, 
            NULL, 
            BCRYPT_ALG_HANDLE_HMAC_FLAG
        );
        if (status < 0) throw std::runtime_error("BCryptOpenAlgorithmProvider failed");

        status = BCryptDeriveKeyPBKDF2(
            alg,
            (PUCHAR)password.data(),
            static_cast<ULONG>(password.size()),
            (PUCHAR)salt.data(),
            static_cast<ULONG>(salt.size()),
            iterations,
            derivedKey.data(),
            static_cast<ULONG>(derivedKey.size()),
            0
        );

        if (status < 0) {
            throw std::runtime_error("DeriveKeyPBKDF2 failed");
        }

        return derivedKey;
    }

    inline std::string DeriveKeyPBKDF2Hex(
        const std::string& password,
        const std::string& salt,
        unsigned int iterations = 100000,
        size_t keyLength = 32
    ) {
        auto key = DeriveKeyPBKDF2(password, salt, iterations, keyLength);
        static const char hexChars[] = "0123456789abcdef";
        std::string hex;
        hex.reserve(key.size() * 2);
        for (uint8_t b : key) {
            hex.push_back(hexChars[(b >> 4) & 0x0F]);
            hex.push_back(hexChars[b & 0x0F]);
        }
        return hex;
    }

    inline std::string MemoryHardPasswordHash(
        const std::string& password,
        const std::string& salt,
        size_t memoryKilobytes = 4096,
        unsigned int passes = 3
    ) {
        auto seed = ComputeSHA256(password + ":" + salt);

        size_t blockSize = 1024;
        size_t numBlocks = memoryKilobytes;
        std::vector<std::vector<uint8_t>> memory(numBlocks, std::vector<uint8_t>(blockSize));

        std::vector<uint8_t> current = seed;
        for (size_t b = 0; b < numBlocks; ++b) {
            for (size_t i = 0; i < blockSize; ++i) {
                memory[b][i] = current[i % current.size()] ^ static_cast<uint8_t>((b * 31 + i) & 0xFF);
            }
            std::string blockStr(memory[b].begin(), memory[b].end());
            current = ComputeSHA256(blockStr);
        }

        for (unsigned int p = 0; p < passes; ++p) {
            for (size_t b = 0; b < numBlocks; ++b) {
                size_t prevBlock = (b == 0) ? (numBlocks - 1) : (b - 1);
                uint32_t jumpIndex = (static_cast<uint32_t>(memory[prevBlock][0]) |
                                     (static_cast<uint32_t>(memory[prevBlock][1]) << 8)) % numBlocks;
                for (size_t i = 0; i < blockSize; ++i) {
                    memory[b][i] ^= memory[jumpIndex][i] + static_cast<uint8_t>(p);
                }
            }
        }

        std::string finalBlock(memory[numBlocks - 1].begin(), memory[numBlocks - 1].end());
        auto finalHash = ComputeSHA256(finalBlock);

        for (auto& blk : memory) {
            SecureZeroMemory(blk.data(), blk.size());
        }

        static const char hexChars[] = "0123456789abcdef";
        std::string hex;
        for (uint8_t b : finalHash) {
            hex.push_back(hexChars[(b >> 4) & 0x0F]);
            hex.push_back(hexChars[b & 0x0F]);
        }
        return hex;
    }

} // namespace Hash
} // namespace LapaCrypto
