#pragma once

#define FEATURE_ADAPTER 1
#define FEATURE_TLS 0
#define FEATURE_FILELOG 1
#define FEATURE_WATCHDOG 1

/*
* Edit this file for best build
*/

/*
*   LOGGER 0 // turn off logging (fully quiet mode)
*   LOGGER 1 // simple logging (not yet supported)
*   LOGGER 2 // normal logging (recommended) ; default
*/
#define LOGGER 2

/*
*   MULTI_CORE 0 // single core machine
*   MULTI_CORE 1 // multiple core machine
*   MULTI_CORE 2 // single/multiple core machine (detect automatically) ; default
*/
#define MULTI_CORE 2

//#define SSE2_SUPPORTED // uncomment to unconditional use of sse2
#define SSSE3_SUPPORTED // uncomment to unconditional use of sss3
//#define AVX2_SUPPORTED // uncomment to unconditional use of avx2 (don't forget to add -mavx2 for gcc/clang)
//#define SHA512_SKIP
//#define AES_VAES_SKIP






// do not remove this include
// it must be at end of this file
#include "proxtopus/conf_def.h"
