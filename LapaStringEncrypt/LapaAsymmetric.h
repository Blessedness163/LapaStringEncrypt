#pragma once

#include <windows.h>
#include <bcrypt.h>
#include <cstdint>
#include <vector>
#include <string>
#include <stdexcept>

#pragma comment(lib, "bcrypt.lib")

namespace LapaCrypto {
namespace Asymmetric {

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

    struct RSAKeyPair {
        std::vector<uint8_t> publicKey;
        std::vector<uint8_t> privateKey;
    };

    struct ECCKeyPair {
        std::vector<uint8_t> publicKey;
        std::vector<uint8_t> privateKey;
    };

    inline RSAKeyPair GenerateRSAKeyPair(DWORD keyBits = 2048) {
        Detail::ScopedAlg alg;
        Detail::ScopedKey key;
        RSAKeyPair keyPair;

        NTSTATUS status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_RSA_ALGORITHM, NULL, 0);
        if (status < 0) throw std::runtime_error("BCryptOpenAlgorithmProvider failed");

        status = BCryptGenerateKeyPair(alg, &key, keyBits, 0);
        if (status >= 0) {
            status = BCryptFinalizeKeyPair(key, 0);
        }

        if (status >= 0) {
            ULONG cbPublic = 0;
            BCryptExportKey(key, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, 0, &cbPublic, 0);
            keyPair.publicKey.resize(cbPublic);
            BCryptExportKey(key, NULL, BCRYPT_RSAPUBLIC_BLOB, keyPair.publicKey.data(), cbPublic, &cbPublic, 0);

            ULONG cbPrivate = 0;
            BCryptExportKey(key, NULL, BCRYPT_RSAPRIVATE_BLOB, NULL, 0, &cbPrivate, 0);
            keyPair.privateKey.resize(cbPrivate);
            BCryptExportKey(key, NULL, BCRYPT_RSAPRIVATE_BLOB, keyPair.privateKey.data(), cbPrivate, &cbPrivate, 0);
        }

        if (status < 0) {
            throw std::runtime_error("Failed to generate RSA key pair");
        }

        return keyPair;
    }

    inline std::vector<uint8_t> EncryptRSA(
        const std::string& plaintext,
        const std::vector<uint8_t>& publicKeyBlob
    ) {
        Detail::ScopedAlg alg;
        Detail::ScopedKey key;
        std::vector<uint8_t> ciphertext;

        NTSTATUS status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_RSA_ALGORITHM, NULL, 0);
        if (status < 0) throw std::runtime_error("BCryptOpenAlgorithmProvider failed");

        status = BCryptImportKeyPair(
            alg, 
            NULL, 
            BCRYPT_RSAPUBLIC_BLOB, 
            &key, 
            (PUCHAR)publicKeyBlob.data(), 
            static_cast<ULONG>(publicKeyBlob.size()), 
            0
        );

        if (status >= 0) {
            BCRYPT_OAEP_PADDING_INFO paddingInfo{};
            paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;

            ULONG cbCipher = 0;
            status = BCryptEncrypt(
                key,
                (PUCHAR)plaintext.data(),
                static_cast<ULONG>(plaintext.size()),
                &paddingInfo,
                NULL,
                0,
                NULL,
                0,
                &cbCipher,
                BCRYPT_PAD_OAEP
            );

            if (status >= 0) {
                ciphertext.resize(cbCipher);
                status = BCryptEncrypt(
                    key,
                    (PUCHAR)plaintext.data(),
                    static_cast<ULONG>(plaintext.size()),
                    &paddingInfo,
                    NULL,
                    0,
                    ciphertext.data(),
                    cbCipher,
                    &cbCipher,
                    BCRYPT_PAD_OAEP
                );
            }
        }

        if (status < 0) {
            throw std::runtime_error("BCryptEncrypt RSA-OAEP failed");
        }

        return ciphertext;
    }

    inline std::string DecryptRSA(
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& privateKeyBlob
    ) {
        Detail::ScopedAlg alg;
        Detail::ScopedKey key;
        std::string plaintext;

        NTSTATUS status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_RSA_ALGORITHM, NULL, 0);
        if (status < 0) throw std::runtime_error("BCryptOpenAlgorithmProvider failed");

        status = BCryptImportKeyPair(
            alg, 
            NULL, 
            BCRYPT_RSAPRIVATE_BLOB, 
            &key, 
            (PUCHAR)privateKeyBlob.data(), 
            static_cast<ULONG>(privateKeyBlob.size()), 
            0
        );

        if (status >= 0) {
            BCRYPT_OAEP_PADDING_INFO paddingInfo{};
            paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;

            ULONG cbPlain = 0;
            status = BCryptDecrypt(
                key,
                (PUCHAR)ciphertext.data(),
                static_cast<ULONG>(ciphertext.size()),
                &paddingInfo,
                NULL,
                0,
                NULL,
                0,
                &cbPlain,
                BCRYPT_PAD_OAEP
            );

            if (status >= 0) {
                std::vector<uint8_t> plainBuf(cbPlain);
                status = BCryptDecrypt(
                    key,
                    (PUCHAR)ciphertext.data(),
                    static_cast<ULONG>(ciphertext.size()),
                    &paddingInfo,
                    NULL,
                    0,
                    plainBuf.data(),
                    cbPlain,
                    &cbPlain,
                    BCRYPT_PAD_OAEP
                );
                if (status >= 0) {
                    plaintext.assign(plainBuf.begin(), plainBuf.begin() + cbPlain);
                }
            }
        }

        if (status < 0) {
            throw std::runtime_error("BCryptDecrypt RSA-OAEP failed");
        }

        return plaintext;
    }

    inline ECCKeyPair GenerateECCKeyPair() {
        Detail::ScopedAlg alg;
        Detail::ScopedKey key;
        ECCKeyPair keyPair;

        NTSTATUS status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0);
        if (status < 0) throw std::runtime_error("BCryptOpenAlgorithmProvider failed");

        status = BCryptGenerateKeyPair(alg, &key, 256, 0);
        if (status >= 0) {
            status = BCryptFinalizeKeyPair(key, 0);
        }

        if (status >= 0) {
            ULONG cbPublic = 0;
            BCryptExportKey(key, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, 0, &cbPublic, 0);
            keyPair.publicKey.resize(cbPublic);
            BCryptExportKey(key, NULL, BCRYPT_ECCPUBLIC_BLOB, keyPair.publicKey.data(), cbPublic, &cbPublic, 0);

            ULONG cbPrivate = 0;
            BCryptExportKey(key, NULL, BCRYPT_ECCPRIVATE_BLOB, NULL, 0, &cbPrivate, 0);
            keyPair.privateKey.resize(cbPrivate);
            BCryptExportKey(key, NULL, BCRYPT_ECCPRIVATE_BLOB, keyPair.privateKey.data(), cbPrivate, &cbPrivate, 0);
        }

        if (status < 0) {
            throw std::runtime_error("Failed to generate ECC key pair");
        }

        return keyPair;
    }

} // namespace Asymmetric
} // namespace LapaCrypto
