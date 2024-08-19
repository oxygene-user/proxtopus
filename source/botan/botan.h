#pragma once

//#include <algorithm>
#undef min

#define _ALLOW_RTCc_IN_STL

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