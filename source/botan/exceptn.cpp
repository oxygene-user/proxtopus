/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "../proxtopus/pch.h"

#include <botan/exceptn.h>

namespace Botan {

    static thread_local bool quiet_error = false;
    void Exception::quiet(bool f)
    {
        quiet_error = f;
    }

std::string to_string(ErrorType type) {
   switch(type) {
      case ErrorType::Unknown:
         return "Unknown";
      case ErrorType::SystemError:
         return "SystemError";
      case ErrorType::NotImplemented:
         return "NotImplemented";
      case ErrorType::OutOfMemory:
         return "OutOfMemory";
      case ErrorType::InternalError:
         return "InternalError";
      case ErrorType::IoError:
         return "IoError";
      case ErrorType::InvalidObjectState:
         return "InvalidObjectState";
      case ErrorType::KeyNotSet:
         return "KeyNotSet";
      case ErrorType::InvalidArgument:
         return "InvalidArgument";
      case ErrorType::InvalidKeyLength:
         return "InvalidKeyLength";
      case ErrorType::InvalidNonceLength:
         return "InvalidNonceLength";
      case ErrorType::LookupError:
         return "LookupError";
      case ErrorType::EncodingFailure:
         return "EncodingFailure";
      case ErrorType::DecodingFailure:
         return "DecodingFailure";
      case ErrorType::TLSError:
         return "TLSError";
      case ErrorType::HttpError:
         return "HttpError";
      case ErrorType::InvalidTag:
         return "InvalidTag";
      case ErrorType::RoughtimeError:
         return "RoughtimeError";
      case ErrorType::CommonCryptoError:
         return "CommonCryptoError";
      case ErrorType::Pkcs11Error:
         return "Pkcs11Error";
      case ErrorType::TPMError:
         return "TPMError";
      case ErrorType::DatabaseError:
         return "DatabaseError";
      case ErrorType::ZlibError:
         return "ZlibError";
      case ErrorType::Bzip2Error:
         return "Bzip2Error";
      case ErrorType::LzmaError:
         return "LzmaError";
   }

   // No default case in above switch so compiler warns
   return "Unrecognized Botan error";
}

Exception::Exception(std::string_view msg) : m_msg(msg) {
    if (!quiet_error)
    {
        LOG_E("exception raised: $", m_msg);
    }
}

Exception::Exception(std::string_view msg, const std::exception& e) {

    if (!quiet_error)
    {
        str::impl_build_string(m_msg, "$ failed with $", msg, e.what());
        LOG_E("exception raised: $", m_msg);
    }
}

Exception::Exception(const char* prefix, std::string_view msg) {
    if (!quiet_error)
    {
        str::impl_build_string(m_msg, "$ $", prefix, msg);
        LOG_E("exception raised: $", m_msg);
    }
}

Invalid_Argument::Invalid_Argument(std::string_view msg) : Exception(msg) {}

Invalid_Argument::Invalid_Argument(std::string_view msg, std::string_view where) : Exception(str::build_string("$ in $", msg, where))
{
}

Invalid_Argument::Invalid_Argument(std::string_view msg, const std::exception& e) : Exception(msg, e) {}

namespace {

std::string format_lookup_error(std::string_view type, std::string_view algo) {
    return str::build_string("Unavailable $ $", type, algo);
}

}  // namespace

Lookup_Error::Lookup_Error(std::string_view type, std::string_view algo) :
      Exception(format_lookup_error(type, algo)) {}

Internal_Error::Internal_Error(std::string_view err) : Exception("Internal error:", err) {}

#if FEATURE_TLS
Unknown_PK_Field_Name::Unknown_PK_Field_Name(ALG algo_name, std::string_view field_name) :
      Invalid_Argument(str::build_string("Unknown field '$' for algorithm $", field_name, algo_name)) {}
#endif

Invalid_Key_Length::Invalid_Key_Length(std::string_view name, size_t length) :
      Invalid_Argument(str::build_string("$ cannot accept a key of length $", name, length)) {}

Invalid_IV_Length::Invalid_IV_Length(std::string_view mode, size_t bad_len) :
      Invalid_Argument(str::build_string("IV length $ is invalid for $", bad_len, mode)) {}

Key_Not_Set::Key_Not_Set(std::string_view algo) : Invalid_State(str::build_string("Key not set in $", algo)) {}

PRNG_Unseeded::PRNG_Unseeded(std::string_view algo) : Invalid_State(str::build_string("PRNG $ not seeded", algo)) {}

Algorithm_Not_Found::Algorithm_Not_Found(std::string_view name) :
      Lookup_Error(str::build_string("Could not find any algorithm named '$'", name)) {}

/// PROXTOPUS : provider removed

Invalid_Algorithm_Name::Invalid_Algorithm_Name(std::string_view name) :
      Invalid_Argument(str::build_string("Invalid algorithm name: '$'", name)) {}

Encoding_Error::Encoding_Error(std::string_view name) : Exception("Encoding error:", name) {}

Decoding_Error::Decoding_Error(std::string_view name) : Exception(name) {}

Decoding_Error::Decoding_Error(std::string_view category, std::string_view err) :
      Exception(str::build_string("$: $", category, err)) {}

Decoding_Error::Decoding_Error(std::string_view msg, const std::exception& e) : Exception(msg, e) {}

Invalid_Authentication_Tag::Invalid_Authentication_Tag(std::string_view msg) :
      Exception("Invalid authentication tag:", msg) {}

Stream_IO_Error::Stream_IO_Error(std::string_view err) : Exception("I/O error:", err) {}

System_Error::System_Error(std::string_view msg, int err_code) :
      Exception(str::build_string("$ error code $", msg, err_code)), m_error_code(err_code) {}

Not_Implemented::Not_Implemented(std::string_view err) : Exception("Not implemented", err) {}

}  // namespace Botan
