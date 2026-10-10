#pragma once

#include <windows.h>
#include <bcrypt.h>
#include <cstdint>
#include <vector>
#include <string>
#include <array>
#include <stdexcept>

#pragma comment(lib, "bcrypt.lib")

namespace LapaCrypto {
namespace Symmetric {

    namespace Detail {
        struct ScopedAlg {
            BCRYPT_ALG_HANDLE handle = NULL;
            ~ScopedAlg() { if (handle) BCryptCloseAlgorithmProvider(handle, 0); }
            operator BCRYPT_ALG_HANDLE() const noexcept { return handle; }
            BCRYPT_ALG_HANDLE* operator&() noexcept { return &handle; }
        };

        struct ScopedKey {
            BCRYPT_KEY_HANDLE handle = NULL;
            ~ScopedKey() { if (handle) BCryptDestroyKey(handle); }
            operator BCRYPT_KEY_HANDLE() const noexcept { return handle; }
            BCRYPT_KEY_HANDLE* operator&() noexcept { return &handle; }
        };
    }

    inline std::string ToHex(const uint8_t* data, size_t len) {
        static const char hexChars[] = "0123456789ABCDEF";
        std::string res;
        res.reserve(len * 2);
        for (size_t i = 0; i < len; ++i) {
            res.push_back(hexChars[(data[i] >> 4) & 0x0F]);
            res.push_back(hexChars[data[i] & 0x0F]);
        }
        return res;
    }

    inline std::string ToHex(const std::vector<uint8_t>& data) {
        return ToHex(data.data(), data.size());
    }

    inline std::vector<uint8_t> FromHex(const std::string& hex) {
        std::vector<uint8_t> bytes;
        for (size_t i = 0; i + 1 < hex.size(); i += 2) {
            uint8_t byte = static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16));
            bytes.push_back(byte);
        }
        return bytes;
    }

    inline std::vector<uint8_t> GenerateSecureRandom(size_t numBytes) {
        std::vector<uint8_t> buffer(numBytes);
        NTSTATUS status = BCryptGenRandom(NULL, buffer.data(), static_cast<ULONG>(numBytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (status < 0) {
            throw std::runtime_error("BCryptGenRandom failed");
        }
        return buffer;
    }

    inline std::vector<uint8_t> EncryptAES256(
        const std::string& plaintext,
        const std::vector<uint8_t>& key256,
        const std::vector<uint8_t>& iv16
    ) {
        if (key256.size() != 32 || iv16.size() != 16) {
            throw std::invalid_argument("Invalid AES-256 key or IV size");
        }

        Detail::ScopedAlg alg;
        Detail::ScopedKey key;
        std::vector<uint8_t> ciphertext;

        NTSTATUS status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0);
        if (status < 0) throw std::runtime_error("BCryptOpenAlgorithmProvider failed");

        status = BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
        if (status < 0) throw std::runtime_error("BCryptSetProperty failed");

        status = BCryptGenerateSymmetricKey(alg, &key, NULL, 0, (PUCHAR)key256.data(), static_cast<ULONG>(key256.size()), 0);
        if (status < 0) throw std::runtime_error("BCryptGenerateSymmetricKey failed");

        std::vector<uint8_t> ivCopy = iv16;
        ULONG cbCiphertext = 0;

        status = BCryptEncrypt(
            key,
            (PUCHAR)plaintext.data(),
            static_cast<ULONG>(plaintext.size()),
            NULL,
            ivCopy.data(),
            static_cast<ULONG>(ivCopy.size()),
            NULL,
            0,
            &cbCiphertext,
            BCRYPT_BLOCK_PADDING
        );

        if (status >= 0) {
            ciphertext.resize(cbCiphertext);
            ivCopy = iv16;
            status = BCryptEncrypt(
                key,
                (PUCHAR)plaintext.data(),
                static_cast<ULONG>(plaintext.size()),
                NULL,
                ivCopy.data(),
                static_cast<ULONG>(ivCopy.size()),
                ciphertext.data(),
                cbCiphertext,
                &cbCiphertext,
                BCRYPT_BLOCK_PADDING
            );
        }

        if (status < 0) {
            throw std::runtime_error("BCryptEncrypt failed");
        }

        ciphertext.resize(cbCiphertext);
        return ciphertext;
    }

    inline std::string DecryptAES256(
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& key256,
        const std::vector<uint8_t>& iv16
    ) {
        if (key256.size() != 32 || iv16.size() != 16) {
            throw std::invalid_argument("Invalid AES-256 key or IV size");
        }

        Detail::ScopedAlg alg;
        Detail::ScopedKey key;
        std::string plaintext;

        NTSTATUS status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0);
        if (status < 0) throw std::runtime_error("BCryptOpenAlgorithmProvider failed");

        status = BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
        if (status < 0) throw std::runtime_error("BCryptSetProperty failed");

        status = BCryptGenerateSymmetricKey(alg, &key, NULL, 0, (PUCHAR)key256.data(), static_cast<ULONG>(key256.size()), 0);
        if (status < 0) throw std::runtime_error("BCryptGenerateSymmetricKey failed");

        std::vector<uint8_t> ivCopy = iv16;
        ULONG cbPlaintext = 0;

        status = BCryptDecrypt(
            key,
            (PUCHAR)ciphertext.data(),
            static_cast<ULONG>(ciphertext.size()),
            NULL,
            ivCopy.data(),
            static_cast<ULONG>(ivCopy.size()),
            NULL,
            0,
            &cbPlaintext,
            BCRYPT_BLOCK_PADDING
        );

        if (status >= 0) {
            std::vector<uint8_t> plainBuf(cbPlaintext);
            ivCopy = iv16;
            status = BCryptDecrypt(
                key,
                (PUCHAR)ciphertext.data(),
                static_cast<ULONG>(ciphertext.size()),
                NULL,
                ivCopy.data(),
                static_cast<ULONG>(ivCopy.size()),
                plainBuf.data(),
                cbPlaintext,
                &cbPlaintext,
                BCRYPT_BLOCK_PADDING
            );
            if (status >= 0) {
                plaintext.assign(plainBuf.begin(), plainBuf.begin() + cbPlaintext);
            }
        }

        if (status < 0) {
            throw std::runtime_error("BCryptDecrypt failed");
        }

        return plaintext;
    }

    class ChaCha20Cipher {
    private:
        static inline uint32_t RotL32(uint32_t v, int c) noexcept {
            return (v << c) | (v >> (32 - c));
        }

        static inline void QuarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) noexcept {
            a += b; d ^= a; d = RotL32(d, 16);
            c += d; b ^= c; b = RotL32(b, 12);
            a += b; d ^= a; d = RotL32(d, 8);
            c += d; b ^= c; b = RotL32(b, 7);
        }

        static inline uint32_t Read32LE(const uint8_t* p) noexcept {
            return static_cast<uint32_t>(p[0]) |
                  (static_cast<uint32_t>(p[1]) << 8) |
                  (static_cast<uint32_t>(p[2]) << 16) |
                  (static_cast<uint32_t>(p[3]) << 24);
        }

        static inline void Write32LE(uint8_t* p, uint32_t v) noexcept {
            p[0] = static_cast<uint8_t>(v & 0xFF);
            p[1] = static_cast<uint8_t>((v >> 8) & 0xFF);
            p[2] = static_cast<uint8_t>((v >> 16) & 0xFF);
            p[3] = static_cast<uint8_t>((v >> 24) & 0xFF);
        }

    public:
        static std::vector<uint8_t> Process(
            const uint8_t* input,
            size_t length,
            const std::vector<uint8_t>& key32,
            const std::vector<uint8_t>& nonce12,
            uint32_t initialCounter = 1
        ) {
            if (key32.size() != 32 || nonce12.size() != 12) {
                throw std::invalid_argument("Invalid ChaCha20 key or nonce size");
            }

            std::vector<uint8_t> output(length);

            uint32_t state[16];
            state[0] = 0x61707865;
            state[1] = 0x3320646e;
            state[2] = 0x79622d32;
            state[3] = 0x6b206574;

            for (int i = 0; i < 8; ++i) {
                state[4 + i] = Read32LE(key32.data() + i * 4);
            }

            state[12] = initialCounter;
            state[13] = Read32LE(nonce12.data() + 0);
            state[14] = Read32LE(nonce12.data() + 4);
            state[15] = Read32LE(nonce12.data() + 8);

            size_t offset = 0;
            uint8_t keyStream[64];

            while (offset < length) {
                uint32_t workingState[16];
                for (int i = 0; i < 16; ++i) workingState[i] = state[i];

                for (int i = 0; i < 10; ++i) {
                    QuarterRound(workingState[0], workingState[4], workingState[8],  workingState[12]);
                    QuarterRound(workingState[1], workingState[5], workingState[9],  workingState[13]);
                    QuarterRound(workingState[2], workingState[6], workingState[10], workingState[14]);
                    QuarterRound(workingState[3], workingState[7], workingState[11], workingState[15]);

                    QuarterRound(workingState[0], workingState[5], workingState[10], workingState[15]);
                    QuarterRound(workingState[1], workingState[6], workingState[11], workingState[12]);
                    QuarterRound(workingState[2], workingState[7], workingState[8],  workingState[13]);
                    QuarterRound(workingState[3], workingState[4], workingState[9],  workingState[14]);
                }

                for (int i = 0; i < 16; ++i) {
                    Write32LE(keyStream + i * 4, workingState[i] + state[i]);
                }

                size_t blockSize = (length - offset < 64) ? (length - offset) : 64;
                for (size_t i = 0; i < blockSize; ++i) {
                    output[offset + i] = input[offset + i] ^ keyStream[i];
                }

                offset += blockSize;
                state[12]++;
            }

            SecureZeroMemory(keyStream, sizeof(keyStream));
            return output;
        }
    };

    inline std::vector<uint8_t> EncryptChaCha20(
        const std::string& plaintext,
        const std::vector<uint8_t>& key32,
        const std::vector<uint8_t>& nonce12,
        uint32_t counter = 1
    ) {
        return ChaCha20Cipher::Process(
            reinterpret_cast<const uint8_t*>(plaintext.data()),
            plaintext.size(),
            key32,
            nonce12,
            counter
        );
    }

    inline std::string DecryptChaCha20(
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& key32,
        const std::vector<uint8_t>& nonce12,
        uint32_t counter = 1
    ) {
        auto decrypted = ChaCha20Cipher::Process(
            ciphertext.data(),
            ciphertext.size(),
            key32,
            nonce12,
            counter
        );
        return std::string(decrypted.begin(), decrypted.end());
    }

} // namespace Symmetric
} // namespace LapaCrypto
