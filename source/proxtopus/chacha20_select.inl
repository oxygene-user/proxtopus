


#ifdef AVX2_SUPPORTED
    m_impl = std::make_unique<IMPLAVX2>();
#elif defined SSSE3_SUPPORTED

#ifdef MODE64
    if (Botan::CPUID::has(Botan::CPUID::Feature::AVX2))
        m_impl = std::make_unique<IMPLAVX2>();
    else
#endif
        m_impl = std::make_unique<IMPLSSSE3>();

#else

#ifdef MODE64
    if (Botan::CPUID::has(Botan::CPUID::Feature::AVX2))
        m_impl = std::make_unique<IMPLAVX2>();
    else
#endif
    if (Botan::CPUID::has(Botan::CPUID::Feature::SSSE3))
        m_impl = std::make_unique<IMPLSSSE3>();
    else
        m_impl = std::make_unique<IMPREF>();
#endif

