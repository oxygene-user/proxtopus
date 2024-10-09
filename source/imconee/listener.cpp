#include "pch.h"

listener* listener::build(loader &ldr, const str::astr& name, const asts& bb)
{
	str::astr t = bb.get_string(ASTR("type"));
	if (t.empty())
	{
		ldr.exit_code = EXIT_FAIL_TYPE_UNDEFINED;
		LOG_E("{type} not defined for lisnener [%s]; type {imconee help listener} for more information", str::printable(name));
		return nullptr;
	}

	if (ASTR("tcp") == t)
	{
		tcp_listener *tcpl = new tcp_listener(ldr, name, bb);
		if (ldr.exit_code != EXIT_OK)
		{
			delete tcpl;
			return nullptr;
		}
		return tcpl;
	}
	if (ASTR("udp") == t)
	{
		udp_listener* tcpl = new udp_listener(ldr, name, bb);
		if (ldr.exit_code != EXIT_OK)
		{
			delete tcpl;
			return nullptr;
		}
		return tcpl;
	}

	LOG_E("unknown {type} [%s] for lisnener [%s]; type {imconee help listener} for more information", t.c_str(), str::printable(name));
	ldr.exit_code = EXIT_FAIL_TYPE_UNDEFINED;

	return nullptr;
}

listener::listener(loader& /*ldr*/, const str::astr& name, const asts& /*bb*/)
{
	this->name = name;
}

socket_listener::socket_listener(loader& ldr, const str::astr& name, const asts& bb, netkit::socket_type st) :listener(ldr, name, bb)
{
	const asts* hnd = bb.get(ASTR("handler"));
	if (nullptr == hnd)
	{
		ldr.exit_code = EXIT_FAIL_NOHANDLER;
		LOG_E("handler not defined for listener [%s]", str::printable(name));
		return;
	}

	handler* h = handler::build(ldr, this, *hnd, st);
	if (h == nullptr)
		return; // no warning message here due it generated by handler::build

	hand.reset(h);

	str::astr bs = bb.get_string(ASTR("bind"));
	netkit::ipap bindaddr = netkit::ipap::parse(bs);

	if (bindaddr.port == 0)
	{
		signed_t port = bb.get_int(ASTR("port"));
		if (0 == port)
		{
			ldr.exit_code = EXIT_FAIL_PORT_UNDEFINED;
			LOG_E("port not defined for listener [%s]", str::printable(name));
			hand.reset();
			return;
		}
		bindaddr.port = (u16)port;

	}
	prepare(bindaddr);

}

void socket_listener::prepare(const netkit::ipap& bind2)
{
	stop();

	auto ss = state.lock_write();
	ss().bind = bind2;
}


void socket_listener::acceptor()
{
	auto ss = state.lock_write();
	ss().stage = ACCEPTOR_WORKS;
	ss.unlock();

	auto r = state.lock_read();
	netkit::ipap bind2 = r().bind;
	r.unlock();

	accept_impl(bind2);

	ss = state.lock_write();
	ss().stage = IDLE;

	spinlock::decrement(glb.numlisteners);
}


/*virtual*/ void socket_listener::open()
{
	auto ss = state.lock_write();
	if (ss().stage != IDLE)
		return;

	ss().stage = ACCEPTOR_START;
	ss.unlock();

	spinlock::increment(glb.numlisteners);

	std::thread th(&tcp_listener::acceptor, this);
	th.detach();
}

/*virtual*/ void socket_listener::stop()
{
	if (state.lock_read()().stage == IDLE)
		return;

	state.lock_write()().need_stop = true;
	hand->stop();

	// holly stupid linux behaviour...
	// we have to make a fake connection to the listening socket so that the damn [accept] will deign to give control.
	// There is no such crap in Windows

#ifdef _NIX
	auto st = state.lock_read();
	netkit::ipap cnct = netkit::ipap::localhost(st().bind.v4);
	if (!st().bind.is_wildcard())
        cnct = st().bind;

    SOCKET s = ::socket(cnct.v4 ? AF_INET : AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    cnct.connect(s);
    closesocket(s);
#endif

	close(false);

	while (state.lock_read()().stage != IDLE)
        Sleep(100);

	state.lock_write()().need_stop = false;
}



tcp_listener::tcp_listener(loader& ldr, const str::astr& name, const asts& bb) :socket_listener(ldr, name, bb, netkit::ST_TCP)
{
	if (!hand->compatible(netkit::ST_TCP))
	{
		ldr.exit_code = EXIT_FAIL_INCOMPATIBLE_HANDLER;
		LOG_E("handler %s is not compatible with listener [%s] (TCP not supported)", str::printable(hand->desc()), str::printable(name));
		return;
	}
}

/*virtual*/ void tcp_listener::accept_impl(const netkit::ipap& bind2)
{
	if (sock.listen(name, bind2))
	{
		LOG_N("listener {%s} has been started (bind ip: %s, port: %i)", str::printable(name), bind2.to_string(false).c_str(), bind2.port);

		for (; !state.lock_read()().need_stop;)
		{
			netkit::tcp_pipe* pipe = sock.tcp_accept(name);
			if (nullptr != pipe)
				hand->on_pipe(pipe);
		}

		hand->stop();
	}

}


udp_listener::udp_listener(loader& ldr, const str::astr& name, const asts& bb) :socket_listener(ldr, name, bb, netkit::ST_UDP)
{
	if (!hand->compatible(netkit::ST_UDP))
	{
		ldr.exit_code = EXIT_FAIL_INCOMPATIBLE_HANDLER;
		LOG_E("handler %s is not compatible with listener [%s] (UDP not supported)", str::printable(hand->desc()), str::printable(name));
		return;
	}
}

/*virtual*/ void udp_listener::accept_impl(const netkit::ipap& bind2)
{
	if (sock.listen_udp(name, bind2))
	{
		LOG_N("listener {%s} has been started (bind ip: %s, port: %i)", str::printable(name), bind2.to_string(false).c_str(), bind2.port);

		for (; !state.lock_read()().need_stop;)
		{
			netkit::udp_packet p(bind2.v4);
			if (sock.recv(p))
				hand->on_udp( sock, p );
		}

		hand->stop();
	}

}
