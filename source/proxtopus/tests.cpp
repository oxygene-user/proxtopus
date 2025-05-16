#include "pch.h"
#include "botan/internal/sha2_64.h"
#ifdef _DEBUG

volatile std::atomic<int> cntt = 0;
#ifdef _WIN32
HANDLE sig;

void query_one_th(const char* s)
{
	++cntt;
	WaitForSingleObject(sig, INFINITE);
	auto rslt = glb.dns->resolve(s, true);
	LOG_D("dns test result: $ -> $", s, rslt.to_string(true));
	--cntt;

	Print();
}

void query_one(const char* s)
{
	std::thread th(query_one_th, s);
	th.detach();
}
#endif

void printator()
{
	while (cntt > 0)
	{
		Print();
		spinlock::sleep(0);
	}
}

    #ifdef _WIN32
void dns_test()
{
	sig = CreateEvent(nullptr, TRUE, FALSE, nullptr);



	query_one("GOOGLE.COM");
	//query_one("ipv6check-http.steamserver.net");
	//query_one("global.prd.cdn.globalsign.com");
	//query_one("pb.adriver.ru");
	//query_one("ipv6.2ip.io");
	//query_one("ns-18-b.gandi.net");
	//query_one("firefox.settings.services.mozilla.com");
	//query_one("101.ru");
	//query_one("cdn1.101.ru");
	//query_one("incoming.telemetry.mozilla.org");
	//query_one("contile.services.mozilla.com");
	//query_one("yastatic.net");
	//query_one("rpc.skcrtxr.com");
	//query_one("ocsp.sectigo.com");

	std::thread th(printator);
	th.detach();

	spinlock::sleep(1000);

	SetEvent(sig);

	for(;cntt != 0;)
		spinlock::sleep(100);

	Print();

	__debugbreak();

}
#endif

void fifo_test()
{
	tools::fifo<int> f;
	srand(2);
	int expected = 0;
	for (int i = 0;i<1000;)
	{
		int cnt = (rand() % 10) + 1;
		for (int k = 0; k < cnt; ++k)
		{
			f.emplace(i);
			++i;
		}
		cnt = (rand() % 10) + 3;
        for (int k = 0; k < cnt; ++k)
        {
			int v = 0;
			if (!f.get(v))
				break;
			if (expected != v)
				DEBUGBREAK();
			++expected;
        }

	}

    for (;;)
    {
        int v = 0;
        if (!f.get(v))
            break;
        if (expected != v)
            DEBUGBREAK();
        ++expected;
    }

	DEBUGBREAK();
}

namespace
{
    struct fb0
    {
        static void* alloc(size_t)
        {
            return nullptr;
        }
    };
}

using ARENA = arena < 8, 512, fb0 >;

void arena_test1(ARENA *a)
{
    void* aa[1024];

    for (int i = 0; i < 1024; ++i)
    {
        aa[i] = a->alloc(8);
    }

	srand(2);

	for (int i = 0; i < 10000000; ++i)
	{
		int j = rand() & 1023;
		if (aa[j])
		{
			a->free(aa[j]);
			aa[j] = nullptr;

			if ((rand() & 3) != 0)
				aa[j] = a->alloc(8);
		}
		else
		{
			aa[j] = a->alloc(8);
		}
	}

    for (int i = 0; i < 1024; ++i)
    {
        if (aa[i]) a->free(aa[i]);
    }

	--cntt;
}

void arena_test()
{
    ARENA a;

	for (int i = 0; i < 8; ++i)
	{
        ++cntt;

        std::thread th(arena_test1, &a);
        th.detach();
	}

    while (cntt > 0)
    {
        Print();
        spinlock::sleep(100);
    }

    DEBUGBREAK();

}

void do_pretests()
{
	for (int i = 2; i < static_cast<int>(Botan::oid_index::_count); ++i)
	{
		auto cmp = Botan::compare_spans(Botan::g_oids[i - 1].id, Botan::g_oids[i].id);
		if (cmp != std::strong_ordering::less)
		{
			//std::vector<u8>
			buffer
				b1, b2;
			b1.assign( Botan::g_oids[i - 1].id.begin(), Botan::g_oids[i - 1].id.end());
			b2.assign(Botan::g_oids[i].id.begin(), Botan::g_oids[i].id.end());
			//bool lesss = b1 < b2;
			DEBUGBREAK();
		}
        cmp = Botan::compare_spans(Botan::g_oids[i].id, Botan::g_oids[i-1].id);
        if (cmp != std::strong_ordering::greater)
            DEBUGBREAK();
	}
    for (int i = 1; i < static_cast<int>(Botan::oid_index::_count); ++i)
    {
        auto fi = Botan::oid_find_index(Botan::g_oids[i].id);
        if (static_cast<int>(fi) != i)
            DEBUGBREAK();
    }
	//__debugbreak();

}

void crash_test()
{
    #ifdef _WIN32
    glb.cfg.crash_log_file = MAKEFN("t:\\testlog.log");
    __try {
        *static_cast<int*>(0) = 1;
    }
    __except (dbg::exceptions_best_friend::exception_filter(GetExceptionInformation()))
    {
    }
    #endif
}

void do_tests()
{
	//crash_test();
    //arena_test();
    //dns_test();
    //fifo_test();
}

#endif

#ifdef DO_SPEED_TESTS

u64 prevt = 0;
inline u64 get_takts()
{
    u64 x = prevt;
    QueryPerformanceCounter(&ref_cast<LARGE_INTEGER>(prevt));
    return prevt - x;
}

void speed_test()
{
    randomgen rng;
    u8 random[1024], outbuf[2048];
    str::astr sss;

    for (; (GetAsyncKeyState(VK_ESCAPE) & 0x8001) != 0x8001;)
    {
        u64 tall0 = 0, tall1 = 0;
        for (signed_t i = 0; i < 1000; ++i)
        {
			sss.clear();
            rng.random_vec(std::span(random));
            str::encode_base64(sss, random, sizeof(random));

            get_takts();
            str::decode_base64(str::view(sss), outbuf, 1024);
            tall0 += get_takts();
			//Botan::base64_decode(std::span(outbuf), str::view(sss)); // Botan::base64_decode is 3x lower then str::decode_base64
			tall1 += get_takts();
        }

        Print("takts $ - $\n", tall0, tall1);
        Print();
    }

}

void do_perf_tests()
{
    //speed_test();
}

#endif