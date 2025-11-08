// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "../conf.h"

#define PROXTOPUS_PCH

#ifdef _WIN32
// Windows Header Files
#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#include <winsock2.h>
#include <ws2ipdef.h>
#include <windows.h>
#include <mmsystem.h>

#include <tchar.h>
#include <in6addr.h>
#endif // _WIN32

#if defined __linux__
#undef _NIX
#define _NIX
#endif

#if defined(__GNUC__) || defined(__clang__)
#define GCC_OR_CLANG
#endif

#ifdef _NIX
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <stdarg.h>
#include <float.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <thread>
#include <poll.h>

#endif

#ifdef GCC_OR_CLANG
#pragma GCC diagnostic ignored "-Wswitch"
#endif

#include <stdlib.h>
#include <malloc.h>
#include <memory.h>

#include <atomic>
#include <memory>
#include <vector>
#include <map>
#include <set>
#include <mutex>
#include <condition_variable>
#include <shared_mutex>
#include <functional>
#include <charconv>
#include <array>

#include <botan/exceptn.h>
#include <botan/rng.h>
#include <botan/internal/tls_server_impl_12.h>
#include <botan/cipher_mode.h>
#include <botan/filter.h>
#include <botan/tls_session_manager_memory.h>

#include "base.h"
#include "str_helpers.h"

#if MULTI_CORE == 0
#define IS_SINGLE_CORE (true)
#define SPINCOUNT_SLEEP(spincount, ...) spinlock::sleep((spincount >> 17) & 0xff); __VA_ARGS__;
#define SPINCOUNT_SLEEP_EX(spincount, thr) spinlock::sleep((spincount >> 17) & 0xff);
#elif MULTI_CORE == 1
#define IS_SINGLE_CORE (false)
#define SPINCOUNT_SLEEP(spincount, ...) if (spincount > 10000) { spinlock::sleep((spincount >> 17) & 0xff); __VA_ARGS__; } else { spinlock::sleep(); }
#define SPINCOUNT_SLEEP_EX(spincount, thr) if (spincount > thr) { spinlock::sleep((spincount >> 17) & 0xff); } else { spinlock::sleep(); }
#else
extern bool g_single_core;
#define IS_SINGLE_CORE (g_single_core)
#define SPINCOUNT_SLEEP(spincount, ...) if (g_single_core || spincount > 10000) { spinlock::sleep((spincount >> 17) & 0xff); __VA_ARGS__; } else { spinlock::sleep(); }
#define SPINCOUNT_SLEEP_EX(spincount, thr) if (g_single_core || spincount > thr) { spinlock::sleep((spincount >> 17) & 0xff); } else { spinlock::sleep(); }
#endif


#include "spinlock.h"

#include "fsys.h"
#include "arena.h"
#include "sts.h"
#ifdef _WIN32
#include "../debug/excpn.h"
#endif
#include "rndgen.h"
#include "ptrs.h"
#include "tools.h"
#include "json.h"
#include "macro.h"
#include "netkit.h"
#include "expression.h"
#include "os_tools.h"
#include "main.h"
#include "resource.h"
#include "tls.h"

#include "chacha20.h"
#include "sodium_poly1305.h"
#include "botan_hash.h"
#include "hmac.h"
#include "hkdf.h"

#include "cmdline.h"
#include "loader.h"
#include "upstream.h"
#include "listener.h"
#include "proxy.h"
#include "ip_machine.h"
#include "adapter.h"

#include "engine.h"
#include "connect.h"
#include "dnsq.h"
#include "watchdog.h"

// reference additional headers your program requires here

#ifndef _NIX
#define DO_SPEED_TESTS
#endif