#pragma once

#include "LapaCommon.h"
#include "LapaCaesar.h"
#include "LapaByteTransform.h"
#include "LapaBase64.h"
#include "LapaXOR.h"
#include "LapaPipeline.h"

#define LAPA_STR(str) \
    ([]() -> auto { \
        static constexpr auto _obf = ::LapaCrypto::ObfuscatedPipeline<char, sizeof(str), \
            ::LapaCrypto::Detail::MakeCompileTimeSeed(__COUNTER__)>(str); \
        return _obf.Decrypt(); \
    }())

#define PROTECT_STR(str) LAPA_STR(str)

#define LAPA_WSTR(wstr) \
    ([]() -> auto { \
        static constexpr auto _obf = ::LapaCrypto::ObfuscatedPipeline<wchar_t, sizeof(wstr) / sizeof(wchar_t), \
            ::LapaCrypto::Detail::MakeCompileTimeSeed(__COUNTER__)>(wstr); \
        return _obf.Decrypt(); \
    }())

#define PROTECT_WSTR(wstr) LAPA_WSTR(wstr)

#define LAPA_USE(str, callExpr) \
    ([&]() -> auto { \
        auto _view = LAPA_STR(str); \
        return (callExpr)(_view.c_str()); \
    }())

#define PROTECT_USE(str, callExpr) LAPA_USE(str, callExpr)

#define LAPA_STORAGE(str) \
    ::LapaCrypto::ObfuscatedPipeline<char, sizeof(str), ::LapaCrypto::Detail::MakeCompileTimeSeed(__COUNTER__)>

#define LAPA_STORAGE_W(wstr) \
    ::LapaCrypto::ObfuscatedPipeline<wchar_t, sizeof(wstr) / sizeof(wchar_t), ::LapaCrypto::Detail::MakeCompileTimeSeed(__COUNTER__)>
