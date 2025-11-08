


#ifdef AVX2_SUPPORTED
    m_impl = std::make_unique<IMPLAVX2>();
#elif defined SSSE3_SUPPORTED

#ifdef ARCH_64BIT
    if (Botan::CPUID::has(Botan::CPUID::Feature::AVX2))
        m_impl = std::make_unique<IMPLAVX2>();
    else
#endif
        m_impl = std::make_unique<IMPLSSSE3>();

#else

#if defined(ARCH_64BIT) && defined(ARCH_X86)
    if (Botan::CPUID::has(Botan::CPUID::Feature::AVX2))
        m_impl = std::make_unique<IMPLAVX2>();
    else
#endif
#ifdef ARCH_X86
    if (Botan::CPUID::has(Botan::CPUID::Feature::SSSE3))
        m_impl = std::make_unique<IMPLSSSE3>();
    else
#endif
        m_impl = std::make_unique<IMPREF>();
#endif

