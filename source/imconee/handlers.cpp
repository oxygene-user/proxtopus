#include "pch.h"

#define BRIDGE_BUFFER_SIZE 65535

handler* handler::build(loader& ldr, listener *owner, const asts& bb)
{
	std::string t = bb.get_string(ASTR("type"));
	if (t.empty())
	{
		ldr.exit_code = EXIT_FAIL_TYPE_UNDEFINED;
		LOG_E("{type} not defined for handler of listener [%s]. Type {imconee help handler} for more information.", str::printable(owner->name));
		return nullptr;
	}

	handler* h = nullptr;
	if (ASTR("direct") == t)
	{
		h = new handler_direct(ldr, owner, bb);
	}
	else if (str::starts_with(t, ASTR("socks")))
	{
		h = new handler_socks(ldr, owner, bb, std::string_view(t).substr(5));
	}
	else if (ASTR("shadowsocks") == t)
	{
		h = new handler_ss(ldr, owner, bb);
	}

	if (h != nullptr)
	{
		if (ldr.exit_code != 0)
		{
			delete h;
			return nullptr;
		}
		return h;
	}

	LOG_E("unknown {type} [%s] for handler of lisnener [%s]. Type {imconee help handler} for more information.", str::printable(t), str::printable(owner->name));
	ldr.exit_code = EXIT_FAIL_TYPE_UNDEFINED;
	return nullptr;
}

handler::handler(loader& ldr, listener* owner, const asts& bb):owner(owner)
{
	std::string pch = bb.get_string(ASTR("proxychain"));
	if (!pch.empty())
	{
		for (str::token<char> tkn(pch, ','); tkn; ++tkn)
		{
			const proxy* p = ldr.find_proxy(*tkn);
			if (p == nullptr)
			{
				LOG_E("unknown {proxy} [%s] for handler of lisnener [%s].", std::string(*tkn).c_str(), str::printable(owner->name));
				ldr.exit_code = EXIT_FAIL_PROXY_NOTFOUND;
				return;
			}
			proxychain.push_back(p);
		}
	}
}

void handler::bridge(netkit::pipe_ptr &&pipe1, netkit::pipe_ptr&& pipe2)
{
	ASSERT(!pipe1->is_multi_ref()); // avoid memory leak! bridge is now owner of pipe1 and pipe2
	ASSERT(!pipe2->is_multi_ref());

	auto st = state.lock_write();
	std::unique_ptr<processing_thread>* ptr = &st().pth;
	bool check_only = false;
	for (processing_thread* t = ptr->get(); t;)
	{
		signed_t x = check_only ? t->check() : t->try_add_bridge(/*ep,*/ pipe1, pipe2);
		if (x < 0)
		{
			t = t->get_next_and_release();
			ptr->reset(t); // it now deletes previous t
			if (t == nullptr)
				break;
		}
		if (x > 0)
			check_only = true;

		ptr = t->get_next_ptr();
		t = t->get_next();
	}

	if (check_only)
		return;

	ASSERT(ptr->get() == nullptr);

	processing_thread *npt = new processing_thread();
	ptr->reset(npt);
	st.unlock();

	npt->try_add_bridge(pipe1, pipe2);
	bridge(npt);

	pipe1 = nullptr;
	pipe2 = nullptr;

	st = state.lock_write();
	ptr = &st().pth;
	for (processing_thread* t = ptr->get(); t;)
	{
		if (t == npt)
		{
			t = t->get_next_and_release();
			ptr->reset(t); // it now deletes previous t
			break;
		}
		ptr = t->get_next_ptr();
		t = t->get_next();
	}
	st.unlock();

}

bool handler::bridged::process(u8* data, netkit::pipe_waiter::mask &masks)
{
	if (masks.have_closed(mask1 | mask2))
		return true;

	if (masks.have_read(mask1))
	{
		signed_t rcvsize = pipe2->send(nullptr, 0) == netkit::pipe::SEND_BUFFERFULL ? 1 : BRIDGE_BUFFER_SIZE;

		signed_t sz = pipe1->recv(data, rcvsize);
		if (sz < 0)
			return true;
		
		if (sz > 0)
		{
			netkit::pipe::sendrslt r = pipe2->send(data, sz);
			if (r == netkit::pipe::SEND_FAIL)
				return true;

			if (r == netkit::pipe::SEND_OK)
				masks.remove_write(mask2);
		}
	}
	if (masks.have_read(mask2))
	{
		signed_t rcvsize = pipe1->send(nullptr, 0) == netkit::pipe::SEND_BUFFERFULL ? 1 : BRIDGE_BUFFER_SIZE;

		signed_t sz = pipe2->recv(data, rcvsize);
		if (sz < 0)
			return true;
		if (sz > 0)
		{
			netkit::pipe::sendrslt r = pipe1->send(data, sz);
			if (r == netkit::pipe::SEND_FAIL)
				return true;

			if (r == netkit::pipe::SEND_OK)
				masks.remove_write(mask1);
		}
	}

	if (masks.have_write(mask1))
	{
		netkit::pipe::sendrslt r = pipe1->send(data, 0); // just send unsent buffer
		if (r == netkit::pipe::SEND_FAIL)
			return true;
	}
	if (masks.have_write(mask2))
	{
		netkit::pipe::sendrslt r = pipe2->send(data, 0); // just send unsent buffer
		if (r == netkit::pipe::SEND_FAIL)
			return true;
	}


	return false;

}

bool handler::processing_thread::tick(u8* data)
{
	spinlock::simple_lock(sync);
	for (signed_t i = 0; i < numslots; ++i)
	{
		if (!slots[i].prepare_wait(waiter))
		{
			--numslots;
			moveslot(i, numslots);
		}
	}

	if (numslots <= 0)
	{
		numslots = -1;
		spinlock::simple_unlock(sync);
		return false;
	}

	spinlock::simple_unlock(sync);


	auto mask = waiter.wait(-1);
	if (mask.is_empty())
		return true;

	spinlock::simple_lock(sync);
	signed_t fixed_numslots = numslots;
	spinlock::simple_unlock(sync);

	signed_t cur_numslots = fixed_numslots;

	for (signed_t i = cur_numslots - 1; i >= 0 && !mask.is_empty(); --i)
	{
		if (slots[i].process(data, mask))
		{
			--cur_numslots;
			moveslot(i, cur_numslots);
		}
	}

	spinlock::simple_lock(sync);
		
	if (fixed_numslots < numslots)
	{
		// looks like new slots were filled during process
		for (signed_t i = fixed_numslots; i < numslots; ++i)
			moveslot(cur_numslots++, i);
	}
	numslots = cur_numslots;
	bool cont_inue = numslots > 0;
	if (!cont_inue)
		numslots = -1; // lock this thread

	spinlock::simple_unlock(sync);

	return cont_inue;
}

void handler::bridge(processing_thread *npt)
{
	u8 data[BRIDGE_BUFFER_SIZE];
	for (; !state.lock_read()().need_stop;)
	{
		if (!npt->tick(data))
			break;

		if (engine::is_stop())
			break;

		auto st = state.lock_write();
		if (processing_thread* next = npt->get_next())
			npt->forward( next );
		st.unlock();
	}
}

netkit::pipe_ptr handler::connect(const netkit::endpoint& addr, bool direct)
{
	static spinlock::long3264 tag = 1;

	if (direct || proxychain.size() == 0)
	{
		if (netkit::pipe* pipe = conn::connect(addr))
		{
			if (proxychain.size() == 0)
			{
				LOG_N("Connected to (%s) via listener [%s]", addr.desc().c_str(), str::printable(owner->name));
			}

			netkit::pipe_ptr pp(pipe);
			return std::move(pipe);
		}

		if (proxychain.size() == 0)
		{
			LOG_N("Not connected to (%s) via listener [%s]", addr.desc().c_str(), str::printable(owner->name));
		}

		return netkit::pipe_ptr();
	}

	spinlock::long3264 t = spinlock::increment(tag);
	std::string stag(ASTR("[")); stag.append(std::to_string(t)); stag.append(ASTR("] "));

	size_t tl = stag.size();

	auto ps = [&](const std::string_view& s)
	{
		stag.resize(tl);
		stag.append(s);
	};

	//LOG_N("Listener {%s} has been started (bind ip: %s, port: %i)", str::printable(name), bind2.to_string().c_str(), port);

	if (proxychain.size() == 1)
	{
		ps("Connecting to upstream proxy (%s) via listener [%s]"); LOG_N(stag.c_str(), proxychain[0]->desc().c_str(), str::printable(owner->name));
	}
	else
	{
		ps("Connecting through proxy chain via listener [%s]"); LOG_N(stag.c_str(), str::printable(owner->name));
		ps("Connecting to proxy (%s)"); LOG_N(stag.c_str(), proxychain[0]->desc().c_str());
	}

	netkit::pipe_ptr pp = connect(proxychain[0]->get_addr(), true);
	
	for (signed_t i = 0; pp != nullptr && i < (signed_t)proxychain.size(); ++i)
	{
		bool finala = i + 1 >= (signed_t)proxychain.size();
		const netkit::endpoint &na = finala ? addr : proxychain[i + 1]->get_addr();
		if (finala)
		{
			ps("Connecting to address (%s)"); LOG_N(stag.c_str(), na.desc().c_str());
		}
		else
		{
			ps("Connecting to proxy (%s)"); LOG_N(stag.c_str(), proxychain[i + 1]->desc().c_str());
		}

		pp = proxychain[i]->prepare(pp, na);
	}
	return std::move(pp);
}

void handler::processing_thread::forward(processing_thread* n)
{
	spinlock::auto_simple_lock a(sync);

	ASSERT(numslots > 0);
	bridged& brlast = slots[numslots - 1];

	if (n->try_add_bridge(brlast.pipe1, brlast.pipe2) > 0)
	{
		--numslots;
		slots[numslots].pipe1 = nullptr;
		slots[numslots].pipe2 = nullptr;
	}

}

void handler::processing_thread::close()
{
	signal();
	{
		std::array<netkit::pipe_ptr, MAXIMUM_SLOTS * 2> ptrs;
		signed_t n = 0;

		spinlock::simple_lock(sync);
		for (signed_t i = 0; i < numslots; ++i)
		{
			ptrs[n++] = std::move(slots[i].pipe1);
			ptrs[n++] = std::move(slots[i].pipe2);
		}
		numslots = 0;
		spinlock::simple_unlock(sync);
	}

	if (next)
		next->close();
}

void handler::stop()
{
	auto ss = state.lock_write();

	if (ss().need_stop)
		return;
	
	ss().need_stop = true;
	if (ss().pth)
		ss().pth->close();
	ss.unlock();

	for (; state.lock_read()().pth != nullptr;)
		Sleep(100);
}


//////////////////////////////////////////////////////////////////////////////////
//
// direct
//
//////////////////////////////////////////////////////////////////////////////////


handler_direct::handler_direct(loader& ldr, listener* owner, const asts& bb):handler(ldr, owner,bb)
{
	to_addr = bb.get_string(ASTR("to"));
	if (!conn::is_valid_addr(to_addr))
	{
		ldr.exit_code = EXIT_FAIL_ADDR_UNDEFINED;
		LOG_E("{to} field of direct handler not defined or invalid (listener: [%s]).", str::printable(owner->name));
	}
}

void handler_direct::on_pipe(netkit::pipe* pipe)
{
	std::thread th(&handler_direct::worker, this, pipe);
	th.detach();

}

void handler_direct::worker(netkit::pipe* pipe)
{
	// now try to connect to out

	netkit::pipe_ptr p(pipe);
	netkit::endpoint ep(to_addr);
	if (netkit::pipe_ptr outcon = connect(ep, false))
		bridge(std::move(p), std::move(outcon));
}


//////////////////////////////////////////////////////////////////////////////////
//
// socks
//
//////////////////////////////////////////////////////////////////////////////////

handler_socks::handler_socks(loader& ldr, listener* owner, const asts& bb, const std::string_view& st) :handler(ldr, owner, bb)
{
	userid = bb.get_string(ASTR("userid"));

	login = bb.get_string(ASTR("auth"));
	size_t dv = login.find(':');
	if (dv != login.npos)
	{
		pass = login.substr(dv + 1);
		login.resize(dv);
	}

	if (login.length() > 254 || pass.length() > 254)
	{
		login.clear();
		pass.clear();
	}

	if (login.empty() || bb.get_bool(ASTR("anon")))
	{
		socks5_allow_anon = true;
	}

	if (st == ASTR("4"))
		allow_5 = false;
	if (st == ASTR("5"))
		allow_4 = false;

}

void handler_socks::on_pipe(netkit::pipe* pipe)
{
	std::thread th(&handler_socks::handshake, this, pipe);
	th.detach();
}

void handler_socks::handshake(netkit::pipe* pipe)
{
	u8 packet[8];
	signed_t rb = pipe->recv(packet, -1);
	if (rb != 1)
		return;

	if (packet[0] == 4)
	{
		handshake4(pipe);
		return;
	}

	if (packet[0] == 5)
	{
		handshake5(pipe);
		return;
	}
}

void handler_socks::handshake4(netkit::pipe* pipe)
{
	if (!allow_4)
		return;

	u8 packet[8];
	signed_t rb = pipe->recv(packet, -7);
	if (rb != 7 || packet[0] != 1)
		return;

	u16 port = (((u16)packet[1]) << 8) | packet[2];
	netkit::ip4 dst = *(netkit::ip4 *)(packet + 3);

	std::string uid;
	for (;;)
	{
		rb = pipe->recv(packet, -1);
		if (rb != 1)
			return;
		if (packet[0] == 0 || uid.size() > 255)
			break;
		uid.push_back(packet[0]);
	}

	if (uid != userid)
	{
		packet[0] = 0;
		packet[1] = 93; // request rejected because the client program and identd report different user - ids
		packet[2] = 0; packet[3] = 0;
		packet[4] = 0; packet[5] = 0; packet[6] = 0; packet[7] = 0;

		pipe->send(packet, 8);
		return;
	}

	netkit::endpoint inf(dst, port);
	worker(pipe, inf, [port, dst](netkit::pipe* p, rslt ec) {

		u8 rp[8];

		rp[0] = 0;

		switch (ec)
		{
		case EC_GRANTED:
			rp[1] = 90;
			break;
		case EC_REMOTE_HOST_UNRCH:
			rp[1] = 92;
			break;
		default:
			rp[1] = 91;
			break;
		}

		rp[2] = (port>>8) & 0xff; rp[3] = port & 0xff;
		*(netkit::ip4*)(rp + 4) = dst;

		p->send(rp, 8);
	});
}

void handler_socks::handshake5(netkit::pipe* pipe)
{
	if (!allow_5)
		return;

	u8 packet[512];
	signed_t rb = pipe->recv(packet, -1);
	if (rb != 1)
		return;

	signed_t numauth = packet[0];
	rb = pipe->recv(packet, -numauth);
	if (numauth != rb)
		return;

	u8 rauth = 0xff;

	for (signed_t i = 0; i < numauth && rauth != 0; ++i)
	{
		switch (packet[i])
		{
		case 0: // anonymous access request
			if (socks5_allow_anon && rauth > 0)
				rauth = 0;
			break;
		case 2:
			if (!login.empty() && rauth > 2)
				rauth = 2;
			break;
		}
	}

	packet[0] = 5;
	packet[1] = rauth;
	if (pipe->send(packet, 2) == netkit::pipe::SEND_FAIL || rauth == 0xff)
		return;

	if (rauth == 2)
	{
		// wait for auth packet
		rb = pipe->recv(packet, -2);
		if (rb != 2 || packet[0] != 1)
			return;
		signed_t loginlen = 1 + packet[1]; // and one byte - len of pass
		rb = pipe->recv(packet, -loginlen);
		if (rb != loginlen)
			return;
		std::string rlogin, rpass;
		rlogin.append((const char *)packet, loginlen - 1);
		signed_t passlen = packet[loginlen - 1];
		rb = pipe->recv(packet, -passlen);
		if (rb != passlen)
			return;
		rpass.append((const char*)packet, passlen);

		if (rlogin != login || rpass != pass)
		{
			packet[0] = 1;
			packet[1] = 1;
			pipe->send(packet, 2);
			return;
		}
		packet[0] = 1;
		packet[1] = 0;
		pipe->send(packet, 2);
	}

	auto fail_answer = [&](u8 code)
	{
		packet[0] = 5; // VER
		packet[1] = code; // REP // FAILURE
		packet[2] = 0;
		packet[3] = 1; // ATYPE // ip4
		packet[4] = 0; packet[5] = 0; packet[6] = 0; packet[7] = 0;
		packet[8] = 0; packet[9] = 0;
		pipe->send(packet, 10);
	};

	rb = pipe->recv(packet, -5);
	if (rb != 5 || packet[0] != 5)
	{
		fail_answer(1); // FAILURE
		return;
	}

	if (packet[1] != 1 /* only CONNECT for now */)
	{
		fail_answer(7); // COMMAND NOT SUPPORTED
		return;
	}

	netkit::endpoint ep;

	switch (packet[3])
	{
	case 1: // ip4
		rb = pipe->recv(packet + 5, -3);
		if (rb != 3)
			return;
		ep.set_ip4(*(netkit::ip4*)(packet + 4));
		break;
	case 3: // domain name

		numauth = packet[4]; // len of domain
		rb = pipe->recv(packet, -numauth);
		if (rb != numauth)
			return;
		ep.set_domain( std::string((const char *)packet, numauth) );
		break;

	case 4: // ipv6
		/* ipv6 not supported yet */
		pipe->recv(packet, -15); // read 15 of 16 bytes of ipv6 address (1st byte already read)
		fail_answer(8); // Address type not supported
		return;
	}

	rb = pipe->recv(packet, -2);
	if (rb != 2)
		return;

	signed_t port = ((signed_t)packet[0]) << 8 | packet[1];
	ep.set_port(port);

	worker(pipe, ep, [port, &ep](netkit::pipe* p, rslt ec) {

		u8 rp[10];

		rp[0] = 5; // VER
		rp[2] = 0;
		rp[3] = 1; // ATYPE // ip4

		switch (ec)
		{
		case EC_GRANTED:
			rp[1] = 0; // SUCCESS
			break;
		case EC_REMOTE_HOST_UNRCH:
			rp[1] = 4;
			break;
		default:
			rp[1] = 1;
			break;
		}

		*(netkit::ip4*)(rp + 4) = ep.get_ip4(false);
		rp[8] = (port >> 8) & 0xff;
		rp[9] = port & 0xff;
		p->send(rp, 10);
	});
}


void handler_socks::worker(netkit::pipe* pipe, const netkit::endpoint &inf, sendanswer answ)
{
	// now try to connect to out

	netkit::pipe_ptr p(pipe);
	if (netkit::pipe_ptr outcon = connect(inf, false))
	{
		answ( pipe, EC_GRANTED );
		bridge(std::move(p), std::move(outcon));
	}
	else {
		answ(pipe, EC_REMOTE_HOST_UNRCH);
	}

}
