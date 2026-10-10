<div align="center">

![LapaCrypto Header](./assets/banner.jpg)

# 🔴 LapaCrypto

**Hardened C++17 Cryptography & Compile-Time String Obfuscation Suite**

<p align="center">
  <img src="https://img.shields.io/badge/C%2B%2B-17-E02424.svg" alt="C++17" />
  <img src="https://img.shields.io/badge/Platform-Windows-9B1C1C.svg" alt="Platform" />
  <img src="https://img.shields.io/badge/Backend-Windows%20CNG-771D1D.svg" alt="Backend" />
  <img src="https://img.shields.io/badge/License-MIT-5C1313.svg" alt="License" />
</p>

<p align="center">
  <b>Header-only</b> • <b>Zero third-party dependencies</b> • <b>5-Stage Compile-Time Cascade</b> • <b>Hardware CNG</b>
</p>

</div>

---

> [!IMPORTANT]
> **Zero Plaintext in `.rdata`**: All string literals protected by `LAPA_STR` / `LAPA_USE` are encrypted across 5 stages during compilation. Decryption is performed exclusively in ephemeral stack memory with instant RAII zeroization via `SecureZeroMemory`.

---

## ⚡ Highlights

- 🔴 **5-Stage Compile-Time Cascade (`LapaStringProtect`)**
  - Polyalphabetic dynamic Caesar $\to$ affine ARX-SBox $\to$ keyed Base64 $\to$ chained ARX-XOR autokey $\to$ FNV-1a checksum.
  - Zero heap allocations; decrypted transiently on the thread stack.
  - Automatic `SecureZeroMemory` wipe upon scope exit.
- 🛡️ **Symmetric Ciphers (`LapaSymmetric`)**
  - **AES-256-CBC** with PKCS#7 padding.
  - **ChaCha20** high-throughput stream cipher (RFC 7539).
- 🔐 **Asymmetric Cryptography (`LapaAsymmetric`)**
  - **RSA-2048** with OAEP padding (SHA-256).
  - **ECC NIST P-256** (`secp256r1`) for ECDSA / ECDH.
- 🩸 **Hashing & Key Derivation (`LapaHash`)**
  - **SHA-256** cryptographic digests.
  - **PBKDF2-HMAC-SHA256** (100,000 rounds with cryptographic salt).
  - **Memory-Hard KDF** (Argon2 design with matrix memory-cost penalty to thwart GPU/ASIC farms).
- 🧪 **Built-in Security Self-Audit**
  - Static disk scanner verifying 0 plaintext occurrences inside the binary.
  - Key tampering sensitivity check and RAM wipe verification.

---

## 📦 Header Reference

| Header | Layer / Category | Description |
|:---|:---|:---|
| [`LapaStringProtect.h`](file:///c:/Users/inrate1337/source/repos/lapaXOREncrypt/lapaXOREncrypt/LapaStringProtect.h) | **Master Entrypoint** | Drop-in macros: `LAPA_STR`, `LAPA_WSTR`, `LAPA_USE` |
| [`LapaCommon.h`](file:///c:/Users/inrate1337/source/repos/lapaXOREncrypt/lapaXOREncrypt/LapaCommon.h) | Primitives | `SplitMix64` PRNG, compile-time seed generation, bit rotations |
| [`LapaCaesar.h`](file:///c:/Users/inrate1337/source/repos/lapaXOREncrypt/lapaXOREncrypt/LapaCaesar.h) | Stage 1 | Dynamic progressive Caesar shift per byte index |
| [`LapaByteTransform.h`](file:///c:/Users/inrate1337/source/repos/lapaXOREncrypt/lapaXOREncrypt/LapaByteTransform.h) | Stage 2 | Bijective affine ARX-SBox ($y = (13x + 7) \bmod 256$) & rotations |
| [`LapaBase64.h`](file:///c:/Users/inrate1337/source/repos/lapaXOREncrypt/lapaXOREncrypt/LapaBase64.h) | Stage 3 | Keyed Base64 scrambler with compile-time Fisher-Yates shuffle |
| [`LapaXOR.h`](file:///c:/Users/inrate1337/source/repos/lapaXOREncrypt/lapaXOREncrypt/LapaXOR.h) | Stage 4 | Multi-round ARX-XOR stream cipher with autokey feedback |
| [`LapaPipeline.h`](file:///c:/Users/inrate1337/source/repos/lapaXOREncrypt/lapaXOREncrypt/LapaPipeline.h) | Stage 5 / Runtime | FNV-1a checksum validation, stack unwinding & RAII wipe |
| [`LapaSymmetric.h`](file:///c:/Users/inrate1337/source/repos/lapaXOREncrypt/lapaXOREncrypt/LapaSymmetric.h) | Symmetric | AES-256-CBC and ChaCha20 via Windows CNG |
| [`LapaAsymmetric.h`](file:///c:/Users/inrate1337/source/repos/lapaXOREncrypt/lapaXOREncrypt/LapaAsymmetric.h) | Asymmetric | RSA-2048 (OAEP SHA-256) and ECC NIST P-256 |
| [`LapaHash.h`](file:///c:/Users/inrate1337/source/repos/lapaXOREncrypt/lapaXOREncrypt/LapaHash.h) | Hash & KDF | SHA-256, PBKDF2 (100k iters), Memory-Hard KDF |

---

## 🚀 Quick Start

### 1. In-Code String Protection
```cpp
#include "LapaStringProtect.h"

void Login() {
    // String is encrypted at compile time. Never appears in .rdata.
    auto token = LAPA_STR("ghp_9482914810293847192837192847");
    
    // Decrypted directly on stack when called:
    std::cout << token.c_str() << '\n';
    
    // Automatically zeroized via SecureZeroMemory upon scope destruction.
}

// Scoped execution with immediate destruction:
LAPA_USE("secret_database_password_2026", [](const char* secret) {
    ConnectDatabase(secret);
});

// Wide strings for WinAPI:
auto wideToken = LAPA_WSTR(L"sk-proj-49182938471928374_SECRET");
```

### 2. Symmetric Encryption (AES-256 & ChaCha20)
```cpp
#include "LapaSymmetric.h"

auto key256  = LapaCrypto::Symmetric::GenerateSecureRandom(32);
auto iv16    = LapaCrypto::Symmetric::GenerateSecureRandom(16);
auto nonce12 = LapaCrypto::Symmetric::GenerateSecureRandom(12);

// AES-256-CBC (PKCS#7):
auto aesCipher = LapaCrypto::Symmetric::EncryptAES256("Classified Data", key256, iv16);
std::string aesPlain = LapaCrypto::Symmetric::DecryptAES256(aesCipher, key256, iv16);

// ChaCha20 (RFC 7539):
auto streamCipher = LapaCrypto::Symmetric::EncryptChaCha20("Payload", key256, nonce12);
std::string streamPlain = LapaCrypto::Symmetric::DecryptChaCha20(streamCipher, key256, nonce12);
```

### 3. Asymmetric Encryption (RSA-2048 & ECC)
```cpp
#include "LapaAsymmetric.h"

// RSA-2048 keypair generation:
auto rsaPair = LapaCrypto::Asymmetric::GenerateRSAKeyPair(2048);

// Public-key encryption with OAEP SHA-256 padding:
auto rsaCipher = LapaCrypto::Asymmetric::EncryptRSA("API_SECRET_KEY", rsaPair.publicKey);

// Private-key decryption:
std::string rsaPlain = LapaCrypto::Asymmetric::DecryptRSA(rsaCipher, rsaPair.privateKey);

// ECC NIST P-256 keypair:
auto eccPair = LapaCrypto::Asymmetric::GenerateECCKeyPair();
```

### 4. Hashing & Password Derivation
```cpp
#include "LapaHash.h"

// SHA-256 digest:
std::string digest = LapaCrypto::Hash::ComputeSHA256Hex("Data");

// PBKDF2-HMAC-SHA256 (100k rounds):
std::string derivedKey = LapaCrypto::Hash::DeriveKeyPBKDF2Hex("Password", "Salt", 100000, 32);

// Memory-Hard KDF (Argon2 design, allocates 2 MB RAM matrix):
std::string memHash = LapaCrypto::Hash::MemoryHardPasswordHash("Password", "Salt", 2048, 2);
```

---

## 🧪 Live Verification Output

```text
[1] Compile-Time String Obfuscation (LapaStringProtect)
    * Original:     "ghp_9482914810293847192837192847"
    * Ciphertext:   03 E0 94 84 5B C7 AD D6 4C 02 D8 3D EB B4 32 4D AD CF 48 D0 E6 B8 45 59 9D 5D 87 24 C4 01 17 3B F1 6D FF 6D 2A 6C 26 DB 44 BD 94 B8
    * Decrypted:    "ghp_9482914810293847192837192847"
    * Verification: [PASS] 5-Layer cascade valid & stack memory wiped

[2] Symmetric Encryption (LapaSymmetric)
  AES-256 (CBC Mode + PKCS#7 Padding):
    * Original:     "Confidential business payload for AES-256-CBC"
    * Ciphertext:   60FC73FFB508C3D7A3710EF72B3A35E25244DBA78BC4A13482DADBF169E2F78F8526485CDBE889B52BD4B35EA7CC7D37
    * Decrypted:    "Confidential business payload for AES-256-CBC"
    * Verification: [PASS] 100% Match

  ChaCha20 (RFC 7539 Stream Cipher):
    * Original:     "High-throughput stream cipher payload ChaCha20 (RFC 7539)"
    * Ciphertext:   6D5A3A7CB55255B8F2818E87D47D8C348D7F6744EC0619798694F8CBC1B77502D16ABAA8D7B186D2E22CA9032941034DE769B8355BE336A6C1
    * Decrypted:    "High-throughput stream cipher payload ChaCha20 (RFC 7539)"
    * Verification: [PASS] 100% Match

[3] Asymmetric Cryptography (LapaAsymmetric)
  RSA-2048 (OAEP SHA-256 Padding):
    * Original:     "CLIENT_SECRET_KEY_RSA_OAEP_2026"
    * Ciphertext:   0661C610990B56D784CCABA6F329FD916F84948DC71BB170EE5FE4BF9175B9E0... [256 bytes]
    * Decrypted:    "CLIENT_SECRET_KEY_RSA_OAEP_2026"
    * Verification: [PASS] 100% Match

  ECC NIST P-256 (secp256r1):
    * Public Key:   45435331200000002F20F3693D8543B615533D730EF1ABA430667834280520CA... (NIST P-256 curve point)
    * Verification: [PASS] Keypair generated for ECDSA/ECDH

[4] Cryptographic Hashing & Key Derivation (LapaHash)
  SHA-256:
    * Original:     "benchmark_cryptographic_input_token"
    * Hash Digest:  dfbd42a12724ce768448c25d2aaec234f4c0b796469cadd7905bd67c288bc3bc
    * Verification: [PASS] 256-bit digest computed

  PBKDF2-HMAC-SHA256 (100,000 iterations):
    * Original:     "MasterPassword" (Salt: "salt_value")
    * Derived Key:  7c0475fc3a608d8c513baca4f5b3f5f87e68dde3c3fef189...
    * Verification: [PASS] Key derived successfully

  Memory-Hard KDF (Argon2 design, 2 MB matrix):
    * Original:     "MasterPassword" (Salt: "salt_value")
    * Derived Hash: 3395d31864d2feaa45bbb97d2692be800c6a1596ee8da605...
    * Verification: [PASS] GPU-resistant memory hash verified

[5] Security Audit & Binary Inspection
    [PASS] Binary Static Analysis: 0 plaintext occurrences inside .exe on disk
    [PASS] Storage Verification: Ciphertext bytes present in .rdata section
    [PASS] AES Key Sensitivity: Tampered 256-bit key rejected
    [PASS] RSA Isolation: Mismatching private key rejected
    [PASS] Memory Sanitization: 100% of buffer zeroed out via SecureZeroMemory
```

---

## 🛠️ Build & Integration

### Requirements
- **OS**: Windows 10 / 11 (x86 or x64)
- **Compiler**: MSVC v143+ with C++17 support (`/std:c++17`)
- **Backend**: Native Windows CNG (`bcrypt.lib`)

### Building via MSBuild
```cmd
msbuild lapaXOREncrypt.sln /p:Configuration=Release /p:Platform=x64
```

### Direct Project Inclusion
1. Copy the `lapaXOREncrypt` header files into your include directory.
2. Link `bcrypt.lib` (automatically requested by headers on MSVC via `#pragma comment(lib, "bcrypt.lib")`).
3. Compile with `/std:c++17` or higher.

---

## 📄 License

Distributed under the [MIT License](LICENSE).

