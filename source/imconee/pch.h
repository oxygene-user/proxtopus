// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#define _ALLOW_RTCc_IN_STL

#define LOGGER 2

#ifdef _WIN32
#include <winsock2.h>
#endif // _WIN32

// Windows Header Files
#include <windows.h>
#include <mmsystem.h>

// C RunTime Header Files
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <tchar.h>

#include <atomic>
#include <memory>
#include <vector>
#include <map>
#include <mutex>
#include <shared_mutex>
#include <functional>
#include <charconv>
#include <array>

#include "rndgen.h"

#include "tools.h"
#include "cmdline.h"
#include "loader.h"
#include "listener.h"
#include "proxy.h"

#include "engine.h"
#include "connect.h"

// reference additional headers your program requires here
