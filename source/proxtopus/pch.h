// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#define LOGGER 2
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
#define ARCH_X86 // assume win32 on x86 arch
#endif // _WIN32

#if defined __linux__
#undef _NIX
#define _NIX
#endif

#if defined(__GNUC__) || defined(__clang__)
#define GCC_OR_CLANG
#if defined(__i386__) || defined(__x86_64__)
#define ARCH_X86
#endif
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
#include <shared_mutex>
#include <functional>
#include <charconv>
#include <array>

#include <botan/exceptn.h>
#include <botan/hmac_drbg.h>
#include <botan/entropy_src.h>
#include <botan/internal/hkdf.h>
#include <botan/internal/hmac.h>
#include <botan/internal/sha1.h>
#include <botan/internal/tls_server_impl_12.h>
#include <botan/cipher_mode.h>
#include <botan/filter.h>
#include <botan/tls_session_manager_memory.h>

#include "base.h"
#include "str_helpers.h"

extern bool g_single_core;
#define IS_SINGLE_CORE (g_single_core)

#include "spinlock.h"
#include "fsys.h"
#include "arena.h"
#include "sts.h"
#ifndef _NIX
#include "../debug/excpn.h"
#endif
#include "rndgen.h"
#include "ptrs.h"
#include "tools.h"
#include "json.h"
#include "macro.h"
#include "netkit.h"
#include "icpt.h"
#include "main.h"
#include "resource.h"
#include "tls.h"

#include "chacha20.h"
#include "sodium_poly1305.h"

#include "cmdline.h"
#include "loader.h"
#include "listener.h"
#include "proxy.h"

#include "engine.h"
#include "connect.h"
#include "dnsq.h"
#include "os_tools.h"
#include "watchdog.h"

// reference additional headers your program requires here

#ifndef _NIX
#define DO_SPEED_TESTS
#endif