#pragma once

// PROXTOPUS : that's all we need from original tls_channel.h

#include <botan/tls_alert.h>
#include <botan/tls_session_manager.h>

namespace Botan::TLS::Channel
{
    static constexpr size_t IO_BUF_DEFAULT_SIZE = 10 * 1024;
}
