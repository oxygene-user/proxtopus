#pragma once

//#include <algorithm>
#undef min

#define BOTAN_DLL
#define BOTAN_IS_BEING_BUILT

#define _ALLOW_RTCc_IN_STL

#if defined (_M_AMD64) || defined (_M_X64) || defined (WIN64) || defined(__LP64__)
#define BOTAN_MP_WORD_BITS 64
#else
#define BOTAN_MP_WORD_BITS 32
#endif

/*
* Define BOTAN_COMPILER_HAS_BUILTIN
*/
#if defined(__has_builtin)
   #define BOTAN_COMPILER_HAS_BUILTIN(x) __has_builtin(x)
#else
   #define BOTAN_COMPILER_HAS_BUILTIN(x) 0
#endif

struct IUnknown;


#include "./internal/md5.h"
#include "./auto_rng.h"
#include "./kdf.h"
#include "./internal/hkdf.h"
#include "./internal/hmac.h"
#include "./internal/sha1.h"
#include "./internal/rotate.h"
#include "./filters.h"
#include "./pipe.h"

namespace Botan
{
}