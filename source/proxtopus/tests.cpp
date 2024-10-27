#include "pch.h"
#ifdef _DEBUG

HANDLE sig;
volatile std::atomic<int> cntt = 0;

void query_one_th(const char* s)
{
	++cntt;
	WaitForSingleObject(sig, INFINITE);
	glb.dns->resolve(s, true);
	--cntt;

	Print();
}

void query_one(const char* s)
{
	std::thread th(query_one_th, s);
	th.detach();
}

void printator()
{
	while (cntt > 0)
	{
		Print();
		Sleep(0);
	}
}

void dns_test()
{
	if (true) return;

	sig = CreateEvent(nullptr, TRUE, FALSE, nullptr);


	
	//query_one("global.prd.cdn.globalsign.com");
	//query_one("pb.adriver.ru");
	//query_one("ipv6.2ip.io");
	//query_one("ns-18-b.gandi.net");
	//query_one("firefox.settings.services.mozilla.com");
	//query_one("101.ru");
	//query_one("cdn1.101.ru");
	//query_one("incoming.telemetry.mozilla.org");
	query_one("contile.services.mozilla.com");
	//query_one("yastatic.net");
	//query_one("rpc.skcrtxr.com");
	//query_one("ocsp.sectigo.com");

	std::thread th(printator);
	th.detach();

	Sleep(1000);

	SetEvent(sig);

	for(;cntt != 0;)
		Sleep(100);

	Print();

	__debugbreak();

}


void fifo_test()
{
	if (true) return;
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
				__debugbreak();
			++expected;
        }

	}

    for (;;)
    {
        int v = 0;
        if (!f.get(v))
            break;
        if (expected != v)
            __debugbreak();
        ++expected;
    }

	__debugbreak();
}






#endif