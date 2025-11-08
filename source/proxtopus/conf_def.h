#pragma once

#ifndef LOGGER
#define LOGGER 2
#endif
#ifndef MULTI_CORE
#define MULTI_CORE 2
#endif

#ifdef _WIN32
#ifndef ARCH_X86
#define ARCH_X86 // assume win32 on x86 arch
#endif
#endif

#if defined(__GNUC__) || defined(__clang__)
#if defined(__i386__) || defined(__x86_64__)
#ifndef ARCH_X86
#define ARCH_X86
#endif
#endif
#endif

#if __GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25)
#define HAVE_GETRANDOM
#endif

#if defined (_M_AMD64) || defined (_M_X64) || defined (WIN64) || defined(__LP64__) || defined(ARCH_64BIT)
// 64 bit
#ifdef ARCH_X86
#ifndef SSE2_SUPPORTED
#define SSE2_SUPPORTED
#endif
#endif

#ifdef AVX2_SUPPORTED
#ifndef SSSE3_SUPPORTED
#define SSSE3_SUPPORTED
#endif
#endif

#else
// 32 bit
#undef AVX2_SUPPORTED
#endif

#ifndef ARCH_X86
#undef SSS2_SUPPORTED
#undef SSSE3_SUPPORTED
#undef AVX2_SUPPORTED
#endif

#ifdef SSE2_SUPPORTED
#include <emmintrin.h>
#endif


#ifdef ANDROID
#undef FEATURE_ADAPTER
#undef FEATURE_TLS
#undef FEATURE_FILELOG
#undef FEATURE_WATCHDOG
#define FEATURE_ADAPTER 0
#define FEATURE_TLS 0
#define FEATURE_FILELOG 0
#define FEATURE_WATCHDOG 0
#endif