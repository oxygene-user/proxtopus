#include "pch.h"
#include "botan/internal/sha2_64.h"
#include "botan/internal/mul128.h"
#ifdef _DEBUG

#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#endif // __GNUC__

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

void chacha_test()
{
	randomgen rng;

	u8 key[32];
	u8 iv[12];

    rng.random_vec(std::span(key));
    rng.random_vec(std::span(iv));

	buffer ib, ob1, ob2;

	auto test_seq1 = [&](std::span<const int> seq)
		{
			int all = 0;
			for (int l : seq) all += l;
			ib.resize(all);
			ob1.resize(all);
			ob2.resize(all);
			rng.random_vec(std::span(ib));

            chacha20 sodium_chacha20;

            sodium_chacha20.set_key(std::span(key));
            sodium_chacha20.set_iv(std::span(iv));

			int disp = 0;
			for (int l : seq)
			{
				sodium_chacha20.cipher(ib.data()+disp, ob2.data()+disp, l);

                //botan_chacha.write_keystream(ob1.data()+disp, l);
                //sodium_chacha20.write_keystream(ob2.data() + disp, l);
				disp += l;
			}

			if (memcmp(ob1.data(), ob2.data(), ob1.size()) != 0)
				DEBUGBREAK();
		};
	auto test_seq = [&](std::initializer_list<int> seq)
		{
			const int* d = seq.begin();
			size_t sz = seq.size();
			test_seq1(std::span<const int>(d,sz));
		};

	test_seq({ 64,2,64,2,64,21,22,23,24 });
    test_seq({ 64,64,64 });
	test_seq({ 61,3,64,64,64 });
	test_seq({ 3,61,51,13,64,64,64 });
    test_seq({ 64,64,64,100 });
    test_seq({ 61,3,64,64,64,100 });
    test_seq({ 3,61,51,13,64,64,64,100 });
    test_seq({ 64,64,64,100 });
    test_seq({ 77,64,64,64,100 });
    test_seq({ 128,64,64,64,100 });
	test_seq({ 128,3,64,64,64,100 });
	test_seq({ 128,3,61,256 });
	test_seq({ 128,3,61,256,127,1,64 });

	std::vector<int> ids;
	for (int i = 0; i < 1000; ++i)
	{
		ids.clear();
		int num = (rand() % 10) + 10;
		for (int j = 0; j < num; ++j)
		{
			int v = (rand() % 1000) + 1;
			if (rand() & 1)
				v = v & (~63);
			ids.push_back(v);
		}
		test_seq1(ids);
	}

	DEBUGBREAK();
}

void mul_test()
{
    u128 a1(math::maximum<u64>::value);
    //u128 b1(math::maximum<u64>::value, math::maximum<u64>::value);
    u128 b1(math::maximum<u64>::value);
    u128 c = a1 * b1;

	uints::uint<8> aa;
	uints::uint<128> bb;
	uints::uint<256> cc = 0;

	//u128 & aaaa = uints::low(cc);
    //const auto &aaaa = uints::low(cc);

	uints::uint<256> s = 11;
    for (int i = 0; i < 6; ++i)
    {
        s = s * s;
    }

    //u32 xxx = 64645653;
    //u64 yyy = 342374892348954534ull;
    //u32 zzz = xxx * yyy;

    uints::uint<32> x32(64645653);
	uints::uint<64> x64(64645653);
	uints::uint<128> x128(64645653234234);
	uints::uint<256> x256(64645653234234);
	uints::uint<64> y64(342374892348954534ull);
    auto z1 = x32 * y64;
	auto z2 = x32 * x128;
	auto z3 = x256 * x128;
	auto z4 = x256 * x32;
    //u64 zv = ref_cast<u64>(z);

	uints::uint<32> asd;
    asd = asd | 333;

    //uint<128> x(33423412313127);
    //uint<128> y(45234512112115);
    //uint<128> w;
    //auto z = uint<128>::umul(x, y, &w);


    randomgen rng;
	uints::uint<32> a = 0, b = 0;
    for (int i = 0; i < 1000000; ++i)
    {
        rng.random_vec(std::span((u8*)&a, sizeof(a)));
        rng.random_vec(std::span((u8*)&b, sizeof(b)));
		u64 v = static_cast<u64>(ref_cast<u32> (a))* ref_cast<u32>(b);
        u32 hi1 = v >> 32;
        u32 lo1 = v & 0xffffffff;

		uints::uint<64> hi2 = uints::uint<64>(a) * b;
        u32 lo2 = (u32)hi2;
        hi2 = hi2 >> 32;

        if (lo1 != lo2 || hi1 != hi2)
            DEBUGBREAK();
    }
    DEBUGBREAK();
}

void do_tests()
{
	//mul_test();
	//chacha_test();
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

void mulspeed()
{
    randomgen rng;
    u64 a = 0, b = 0;
    for (int i = 0; i < 1000; ++i)
    {
        rng.random_vec(std::span((u8*)&a, 8));
        rng.random_vec(std::span((u8*)&b, 8));
        u64 hi1;
        u64 lo1 = _umul128(a, b, &hi1);

        u64 hi2;
        u64 lo2 = _umul128(b, a, &hi2);

        if (lo1 != lo2 || hi1 != hi2)
            __debugbreak();
    }

}

void speed_test()
{
	glb.log_muted = false;
    randomgen rng;
	u8 random[1024], outbuf1[1024] = {}, outbuf2[1024], outbuf3[1024] = {};
	u8 key[32], iv[24];

	rng.random_vec(std::span(key));
	rng.random_vec(std::span(iv));
	rng.random_vec(std::span(random));

	//u8 m[64] = {}, c[64] = {};
	//chacha_cpu(c, m, iv, key);
	//rng.random_vec(std::span(c));
	//chacha_cpu(c, m, iv, key);

	chacha20 sodium_chacha20;
	poly1305 sodium_poly;

	iv[0] |= 0x80;
	random[0] |= 0x80;
	uints::uint<128> x(ref_cast<u128>(iv));
	uints::uint<128> y(ref_cast<u128>(random));
    auto z = x * y;
    LOG_I("a: $, b: $, rslt: $", HEX(0, ref_cast<u128>(iv)), HEX(0, ref_cast<u128>(random)), HEX(0, z));
	Print();
	ref_cast<u64>(key) += (u64)z;

	uints::uint<256> asdasd = ref_cast<uints::uint<256>>(random);
	LOG_I("hextes $ == $", HEX(0, asdasd), DEC(0, asdasd));
    Print();
	asdasd = asdasd >> 141;
    LOG_I("hextes $ == $", HEX(-1, asdasd), DEC(0, asdasd));
	Print();

	uints::divbyconst<decltype(asdasd),10>(asdasd);

    for (; (GetAsyncKeyState(VK_ESCAPE) & 0x8001) != 0x8001;)
    {
        u64 tall0 = 0, tall1 = 0, tall2 = 0, r0 = 0, r1 = 0, r2 = 0;
		u64 ic = 0;

		//sodium_chacha20.set_key(std::span(key));
		//sodium_chacha20.set_iv(std::span(iv));

		sodium_poly.init(key);

        for (signed_t i = 0; i < 1000; ++i)
        {
            rng.random_vec(std::span(random));
			//memset(outbuf1, 0, sizeof(outbuf1));
            //memset(outbuf2, 0, sizeof(outbuf2));

            get_takts();
            //botan_chacha.cipher(random, outbuf1, sizeof(random));
            tall0 += get_takts();
			r0 += outbuf1[100] + outbuf1[999];

			get_takts();
			//crypto_stream_xchacha20_xor_ic(outbuf2, random, sizeof(random), iv, ic, key);
			sodium_poly.update(random);
			//mulspeed();
			tall1 += get_takts();
            r1 += outbuf2[100] + outbuf2[999];

			get_takts();
			//sodium_chacha20.cipher(random, outbuf3, sizeof(random));
            tall2 += get_takts();
            r2 += outbuf3[100] + outbuf3[999];


			Botan::xor_buf(random, outbuf1, 1024);
            ic += sizeof(random) / 64;
        }
		u128 f1, f2;
		sodium_poly.fin((u8*)&f2);

		LOG_I("takts $ - $ ($,$)", tall0, tall1, HEX(0,f1), HEX(0,f2));

        //LOG_I("takts $ - $ - $ ($,$,$)", tall0, tall1, tall2, r0, r1, r2);
        Print();
    }

}

void do_perf_tests()
{
    //speed_test();
}

#endif