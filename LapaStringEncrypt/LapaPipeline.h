#pragma once

#include "LapaCommon.h"
#include "LapaCaesar.h"
#include "LapaByteTransform.h"
#include "LapaBase64.h"
#include "LapaXOR.h"
#include <iomanip>
#include <sstream>

namespace LapaCrypto {
namespace Detail {

    template <typename CharT, size_t N>
    constexpr std::array<uint8_t, N * sizeof(CharT)> ExtractRawBytes(const CharT (&str)[N]) noexcept {
        constexpr size_t TotalBytes = N * sizeof(CharT);
        std::array<uint8_t, TotalBytes> out{};
        if constexpr (sizeof(CharT) == 1) {
            for (size_t i = 0; i < N; ++i) {
                out[i] = static_cast<uint8_t>(str[i]);
            }
        } else {
            for (size_t i = 0; i < N; ++i) {
                uint16_t w = static_cast<uint16_t>(str[i]);
                out[i * 2 + 0] = static_cast<uint8_t>(w & 0xFF);
                out[i * 2 + 1] = static_cast<uint8_t>((w >> 8) & 0xFF);
            }
        }
        return out;
    }

    template <typename CharT, size_t N>
    inline void ReconstructFromRawBytes(const uint8_t* in, CharT* out) noexcept {
        if constexpr (sizeof(CharT) == 1) {
            for (size_t i = 0; i < N; ++i) {
                out[i] = static_cast<CharT>(in[i]);
            }
        } else {
            for (size_t i = 0; i < N; ++i) {
                uint16_t low = in[i * 2 + 0];
                uint16_t high = in[i * 2 + 1];
                out[i] = static_cast<CharT>((high << 8) | low);
            }
        }
    }

} // namespace Detail

    template <typename CharT, size_t N, uint64_t Seed>
    class ObfuscatedPipeline {
    public:
        static constexpr size_t RawBytes = N * sizeof(CharT);
        static constexpr size_t B64Bytes = Detail::Base64EncodedSize(RawBytes);

        constexpr ObfuscatedPipeline(const CharT (&str)[N]) 
            : m_encrypted{}, m_expectedHash(0) 
        {
            auto rawIn = Detail::ExtractRawBytes<CharT, N>(str);
            m_expectedHash = Detail::Fnv1aHash(rawIn.data(), RawBytes);

            auto stage1 = Detail::EncryptCaesar<RawBytes, Seed>(rawIn.data());
            auto stage2 = Detail::TransformBytes<RawBytes, Seed>(stage1.data());
            auto stage3 = Detail::EncodeBase64<RawBytes, Seed>(stage2.data());
            m_encrypted = Detail::EncryptARXXor<B64Bytes, Seed>(stage3);
        }

        class DecryptedView {
        public:
            DecryptedView(const std::array<uint8_t, B64Bytes>& encData, uint32_t expectedHash)
                : m_encPtr(encData.data()), m_expectedHash(expectedHash), m_isValid(false)
            {
                char b64Buf[B64Bytes]{};
                Detail::DecryptARXXor<B64Bytes>(encData.data(), b64Buf, Seed);

                uint8_t stage2Buf[RawBytes]{};
                Detail::DecodeBase64(b64Buf, B64Bytes, stage2Buf, RawBytes, Seed);

                uint8_t stage1Buf[RawBytes]{};
                Detail::UntransformBytes<RawBytes, Seed>(stage2Buf, stage1Buf);

                uint8_t rawDecrypted[RawBytes]{};
                Detail::DecryptCaesar<RawBytes, Seed>(stage1Buf, rawDecrypted);

                uint32_t actualHash = Detail::Fnv1aHash(rawDecrypted, RawBytes);
                m_isValid = (actualHash == m_expectedHash);

                Detail::ReconstructFromRawBytes<CharT, N>(rawDecrypted, m_buffer);

                Detail::SecureWipeMemory(b64Buf, sizeof(b64Buf));
                Detail::SecureWipeMemory(stage2Buf, sizeof(stage2Buf));
                Detail::SecureWipeMemory(stage1Buf, sizeof(stage1Buf));
                Detail::SecureWipeMemory(rawDecrypted, sizeof(rawDecrypted));
            }

            ~DecryptedView() {
                Detail::SecureWipeMemory(m_buffer, sizeof(m_buffer));
            }

            DecryptedView(const DecryptedView&) = delete;
            DecryptedView& operator=(const DecryptedView&) = delete;

            DecryptedView(DecryptedView&& other) noexcept
                : m_encPtr(other.m_encPtr), m_expectedHash(other.m_expectedHash), m_isValid(other.m_isValid)
            {
                for (size_t i = 0; i < N; ++i) m_buffer[i] = other.m_buffer[i];
                Detail::SecureWipeMemory(other.m_buffer, sizeof(other.m_buffer));
                other.m_isValid = false;
            }

            const CharT* c_str() const noexcept { return m_buffer; }
            const CharT* data() const noexcept { return m_buffer; }
            operator const CharT*() const noexcept { return m_buffer; }

            size_t length() const noexcept { return (N > 0) ? (N - 1) : 0; }
            size_t size() const noexcept { return length(); }
            bool empty() const noexcept { return length() == 0; }
            bool IsValid() const noexcept { return m_isValid; }

            std::basic_string<CharT> str() const {
                return std::basic_string<CharT>(m_buffer, length());
            }

            operator std::basic_string<CharT>() const {
                return str();
            }

            const uint8_t* EncryptedData() const noexcept { return m_encPtr; }
            size_t EncryptedSize() const noexcept { return B64Bytes; }

            std::string EncryptedHex() const {
                static const char hexDigits[] = "0123456789ABCDEF";
                std::string res;
                if (!m_encPtr) return res;
                res.reserve(B64Bytes * 3);
                for (size_t i = 0; i < B64Bytes; ++i) {
                    res.push_back(hexDigits[(m_encPtr[i] >> 4) & 0x0F]);
                    res.push_back(hexDigits[m_encPtr[i] & 0x0F]);
                    if (i + 1 < B64Bytes) res.push_back(' ');
                }
                return res;
            }

            void Clear() noexcept {
                Detail::SecureWipeMemory(m_buffer, sizeof(m_buffer));
                m_isValid = false;
            }

            bool operator==(const CharT* other) const noexcept {
                if (!other) return false;
                for (size_t i = 0; i < N; ++i) {
                    if (m_buffer[i] != other[i]) return false;
                    if (m_buffer[i] == 0) break;
                }
                return true;
            }

            bool operator==(const std::basic_string<CharT>& other) const noexcept {
                return str() == other;
            }

            bool operator!=(const CharT* other) const noexcept { return !(*this == other); }
            bool operator!=(const std::basic_string<CharT>& other) const noexcept { return !(*this == other); }

        private:
            CharT m_buffer[N];
            const uint8_t* m_encPtr;
            uint32_t m_expectedHash;
            bool m_isValid;
        };

        DecryptedView Decrypt() const {
            return DecryptedView(m_encrypted, m_expectedHash);
        }

        template <typename Func>
        auto WithPlaintext(Func&& func) const {
            DecryptedView view(m_encrypted, m_expectedHash);
            auto result = func(view.c_str());
            view.Clear();
            return result;
        }

        constexpr size_t Size() const noexcept { return N; }
        const std::array<uint8_t, B64Bytes>& EncryptedData() const noexcept { return m_encrypted; }

        struct StageBreakdown {
            std::string stage1CaesarHex;
            uint8_t caesarBaseShift;
            uint8_t caesarStep;
            std::string stage2ByteHex;
            std::string stage3Base64;
            std::string stage4XorHex;
            uint32_t checksum;
        };

        static StageBreakdown InspectPipeline(const CharT (&str)[N]) {
            static const char hexDigits[] = "0123456789ABCDEF";
            auto rawIn = Detail::ExtractRawBytes<CharT, N>(str);
            uint32_t csum = Detail::Fnv1aHash(rawIn.data(), RawBytes);

            auto s1 = Detail::EncryptCaesar<RawBytes, Seed>(rawIn.data());
            std::string s1Hex;
            for (size_t i = 0; i < RawBytes; ++i) {
                s1Hex.push_back(hexDigits[(s1[i] >> 4) & 0x0F]);
                s1Hex.push_back(hexDigits[s1[i] & 0x0F]);
                if (i + 1 < RawBytes) s1Hex.push_back(' ');
            }

            auto s2 = Detail::TransformBytes<RawBytes, Seed>(s1.data());
            std::string s2Hex;
            for (size_t i = 0; i < RawBytes; ++i) {
                s2Hex.push_back(hexDigits[(s2[i] >> 4) & 0x0F]);
                s2Hex.push_back(hexDigits[s2[i] & 0x0F]);
                if (i + 1 < RawBytes) s2Hex.push_back(' ');
            }

            auto s3 = Detail::EncodeBase64<RawBytes, Seed>(s2.data());
            std::string s3Str(s3.data(), B64Bytes);

            auto s4 = Detail::EncryptARXXor<B64Bytes, Seed>(s3);
            std::string s4Hex;
            for (size_t i = 0; i < B64Bytes; ++i) {
                s4Hex.push_back(hexDigits[(s4[i] >> 4) & 0x0F]);
                s4Hex.push_back(hexDigits[s4[i] & 0x0F]);
                if (i + 1 < B64Bytes) s4Hex.push_back(' ');
            }

            return { s1Hex, Detail::GetCaesarBaseShift(Seed), Detail::GetCaesarStep(Seed), s2Hex, s3Str, s4Hex, csum };
        }

    private:
        std::array<uint8_t, B64Bytes> m_encrypted;
        uint32_t m_expectedHash;
    };

    template <typename CharT, size_t N, uint64_t Seed>
    inline std::basic_ostream<CharT>& operator<<(
        std::basic_ostream<CharT>& os,
        const typename ObfuscatedPipeline<CharT, N, Seed>::DecryptedView& view
    ) {
        return os << view.c_str();
    }

} // namespace LapaCrypto
