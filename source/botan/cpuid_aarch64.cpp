/*
* Runtime CPU detection for Aarch64
* (C) 2009,2010,2013,2017,2020,2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/cpuid.h>
#if defined(ARCH_ARM) && defined(ARCH_64BIT)
#include <botan/assert.h>
#include <optional>

#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   #include <errno.h>
   #include <pthread.h>
   #include <setjmp.h>
   #include <signal.h>
   #include <stdlib.h>
   #include <sys/mman.h>
   #include <sys/resource.h>
   #include <sys/types.h>
   #include <termios.h>
   #include <unistd.h>
   #undef B0
#endif

#if defined(BOTAN_HAS_OS_UTILS)
   #include <botan/internal/os_utils.h>
#endif

#if defined(BOTAN_TARGET_OS_HAS_SYSCTLBYNAME)
   #include <sys/sysctl.h>
   #include <sys/types.h>
#endif

namespace Botan {

namespace {

std::optional<uint32_t> aarch64_feat_via_auxval(uint32_t allowed) {
#if defined(BOTAN_HAS_OS_UTILS)

   if(auto auxval = OS::get_auxval_hwcap()) {
      uint32_t feat = 0;

      /*
      * On systems with getauxval these bits should normally be defined
      * in bits/auxv.h but some buggy? glibc installs seem to miss them.
      * These following values are all fixed, for the Linux ELF format,
      * so we just hardcode them in ARM_hwcap_bit enum.
      */
      enum class ARM_hwcap_bit : uint64_t {
         NEON_bit = (1 << 1),
         AES_bit = (1 << 3),
         PMULL_bit = (1 << 4),
         SHA1_bit = (1 << 5),
         SHA2_bit = (1 << 6),
         SHA3_bit = (1 << 17),
         SM3_bit = (1 << 18),
         SM4_bit = (1 << 19),
         SHA2_512_bit = (1 << 21),
         SVE_bit = (1 << 22),
      };

      const auto hwcap = auxval->first;

      feat |= CPUID::if_set(hwcap, ARM_hwcap_bit::NEON_bit, CPUFeature::Bit::NEON, allowed);

      if(feat & CPUFeature::Bit::NEON) {
         feat |= CPUID::if_set(hwcap, ARM_hwcap_bit::AES_bit, CPUFeature::Bit::AES, allowed);
         feat |= CPUID::if_set(hwcap, ARM_hwcap_bit::PMULL_bit, CPUFeature::Bit::PMULL, allowed);
         feat |= CPUID::if_set(hwcap, ARM_hwcap_bit::SHA1_bit, CPUFeature::Bit::SHA1, allowed);
         feat |= CPUID::if_set(hwcap, ARM_hwcap_bit::SHA2_bit, CPUFeature::Bit::SHA2, allowed);
         feat |= CPUID::if_set(hwcap, ARM_hwcap_bit::SHA3_bit, CPUFeature::Bit::SHA3, allowed);
         feat |= CPUID::if_set(hwcap, ARM_hwcap_bit::SM3_bit, CPUFeature::Bit::SM3, allowed);
         feat |= CPUID::if_set(hwcap, ARM_hwcap_bit::SM4_bit, CPUFeature::Bit::SM4, allowed);
         feat |= CPUID::if_set(hwcap, ARM_hwcap_bit::SHA2_512_bit, CPUFeature::Bit::SHA2_512, allowed);
         feat |= CPUID::if_set(hwcap, ARM_hwcap_bit::SVE_bit, CPUFeature::Bit::SVE, allowed);
      }

      return feat;
   }
#else
   BOTAN_UNUSED(allowed);
#endif

   return {};
}

std::optional<uint32_t> aarch64_feat_using_mac_api(uint32_t allowed) {
#if defined(BOTAN_TARGET_OS_IS_IOS) || defined(BOTAN_TARGET_OS_IS_MACOS)
   uint32_t feat = 0;

   auto sysctlbyname_has_feature = [](const char* feature_name) -> bool {
      unsigned int feature;
      size_t size = sizeof(feature);
      ::sysctlbyname(feature_name, &feature, &size, nullptr, 0);
      return (feature == 1);
   };

   // All 64-bit Apple ARM chips have NEON, AES, and SHA support
   feat |= CPUFeature::Bit::NEON & allowed;
   if(feat & CPUFeature::Bit::NEON) {
      feat |= CPUFeature::Bit::AES & allowed;
      feat |= CPUFeature::Bit::PMULL & allowed;
      feat |= CPUFeature::Bit::SHA1 & allowed;
      feat |= CPUFeature::Bit::SHA2 & allowed;

      if(sysctlbyname_has_feature("hw.optional.armv8_2_sha3")) {
         feat |= CPUFeature::Bit::SHA3 & allowed;
      }
      if(sysctlbyname_has_feature("hw.optional.armv8_2_sha512")) {
         feat |= CPUFeature::Bit::SHA2_512 & allowed;
      }
   }

   return feat;
#else
   BOTAN_UNUSED(allowed);
   return {};
#endif
}

#if defined(BOTAN_TARGET_OS_HAS_POSIX1) && !defined(BOTAN_TARGET_OS_IS_EMSCRIPTEN)

namespace {

// NOLINTNEXTLINE(*-avoid-non-const-global-variables)
::sigjmp_buf g_sigill_jmp_buf;

void botan_sigill_handler(int /*unused*/) {
   siglongjmp(g_sigill_jmp_buf, /*non-zero return value*/ 1);
}

}  // namespace

#endif

int run_cpu_instruction_probe(const std::function<int()>& probe_fn) {
   volatile int probe_result = -3;

#if defined(BOTAN_TARGET_OS_HAS_POSIX1) && !defined(BOTAN_TARGET_OS_IS_EMSCRIPTEN)

   struct sigaction old_sigaction;
   struct sigaction sigaction;

   sigaction.sa_handler = botan_sigill_handler;
   sigemptyset(&sigaction.sa_mask);
   sigaction.sa_flags = 0;

   int rc = ::sigaction(SIGILL, &sigaction, &old_sigaction);

   if(rc != 0) {
      throw System_Error("run_cpu_instruction_probe sigaction failed", errno);
   }

   rc = sigsetjmp(g_sigill_jmp_buf, /*save sigs*/ 1);

   if(rc == 0) {
      // first call to sigsetjmp
      probe_result = probe_fn();
   } else if(rc == 1) {
      // non-local return from siglongjmp in signal handler: return error
      probe_result = -1;
   }

   // Restore old SIGILL handler, if any
   rc = ::sigaction(SIGILL, &old_sigaction, nullptr);
   if(rc != 0) {
      throw System_Error("run_cpu_instruction_probe sigaction restore failed", errno);
   }

#else
   BOTAN_UNUSED(probe_fn);
#endif

   return probe_result;
}


std::optional<uint32_t> aarch64_feat_using_instr_probe(uint32_t allowed) {
#if defined(BOTAN_USE_GCC_INLINE_ASM)

   /*
   No getauxval API available, fall back on probe functions.
   NEON registers v0-v7 are caller saved in Aarch64
   */

   auto neon_probe = []() noexcept -> int {
      asm("and v0.16b, v0.16b, v0.16b");
      return 1;
   };
   auto aes_probe = []() noexcept -> int {
      asm(".word 0x4e284800");
      return 1;
   };
   auto pmull_probe = []() noexcept -> int {
      asm(".word 0x0ee0e000");
      return 1;
   };
   auto sha1_probe = []() noexcept -> int {
      asm(".word 0x5e280800");
      return 1;
   };
   auto sha2_probe = []() noexcept -> int {
      asm(".word 0x5e282800");
      return 1;
   };
   auto sha512_probe = []() noexcept -> int {
      asm(".long 0xcec08000");
      return 1;
   };

   uint32_t feat = 0;
   if(allowed & CPUFeature::Bit::NEON) {
      if(run_cpu_instruction_probe(neon_probe) == 1) {
         feat |= CPUFeature::Bit::NEON;
      }

      if(feat & CPUFeature::Bit::NEON) {
         if(run_cpu_instruction_probe(aes_probe) == 1) {
            feat |= CPUFeature::Bit::AES & allowed;
         }
         if(run_cpu_instruction_probe(pmull_probe) == 1) {
            feat |= CPUFeature::Bit::PMULL & allowed;
         }
         if(run_cpu_instruction_probe(sha1_probe) == 1) {
            feat |= CPUFeature::Bit::SHA1 & allowed;
         }
         if(run_cpu_instruction_probe(sha2_probe) == 1) {
            feat |= CPUFeature::Bit::SHA2 & allowed;
         }
         if(run_cpu_instruction_probe(sha512_probe) == 1) {
            feat |= CPUFeature::Bit::SHA2_512 & allowed;
         }
      }
   }

   return feat;
#else
   BOTAN_UNUSED(allowed);
   return {};
#endif
}

}  // namespace

uint32_t CPUID::CPUID_Data::detect_cpu_features(uint32_t allowed) {
   if(auto feat_aux = aarch64_feat_via_auxval(allowed)) {
      return feat_aux.value();
   } else if(auto feat_mac = aarch64_feat_using_mac_api(allowed)) {
      return feat_mac.value();
   } else if(auto feat_instr = aarch64_feat_using_instr_probe(allowed)) {
      return feat_instr.value();
   } else {
      return 0;
   }
}

}  // namespace Botan
#endif