#pragma once

/*
* Edit this file for best build
*/

#define ARCH_X86

/*
*   LOGGER 0 // turn off logging (fully quiet mode)
*   LOGGER 1 // simple logging (not yet supported)
*   LOGGER 2 // normal logging (recommended) ; default
*/
#define LOGGER 2

#define HAVE_GETRANDOM // linux only

/*
*   MULTI_CORE 0 // single core machine
*   MULTI_CORE 1 // multiple core machine
*   MULTI_CORE 2 // single/multiple core machine (detect automatically) ; default
*/
#define MULTI_CORE 2

//#define SSE2_SUPPORTED // uncomment to unconditional use of sse2
//#define SSSE3_SUPPORTED // uncomment to unconditional use of sss3
//#define AVX2_SUPPORTED // uncomment to unconditional use of avx2