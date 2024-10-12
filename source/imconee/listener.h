#pragma once

#include "netkit.h"
#include "handlers.h"

class loader;
class proxy;
class listener;
using larray = std::vector<std::unique_ptr<listener>>;

class listener
{
protected:
	str::astr name;
	std::unique_ptr<handler> hand;
public:

#ifdef _DEBUG
	u32 accept_tid = 0;
#endif // _DEBUG

	listener(loader& ldr, const str::astr& name, const asts& bb);
	virtual ~listener() {}

	virtual void open() = 0;
	virtual void stop() = 0;
	virtual void close(bool fbc) = 0;

	const str::astr& get_name() const
	{
		return name;
	}

	static void build(larray &arr, loader& ldr, const str::astr& name, const asts& bb);
};

class socket_listener : public listener
{
	enum state_stage : u8
	{
		IDLE,
		ACCEPTOR_START,
		ACCEPTOR_WORKS,
	};

	struct statestruct
	{
		netkit::ipap bind;
		state_stage stage = IDLE;
		bool need_stop = false;
	};

	static_assert(sizeof(statestruct) == 24);

protected:
	spinlock::syncvar<statestruct> state;
	void acceptor();
	virtual void accept_impl(const netkit::ipap& bind2) = 0;
	NIXONLY(virtual void kick_socket()=0);
public:

	socket_listener(loader& ldr, const str::astr& name, const asts& bb, netkit::socket_type st);
	/*virtual*/ ~socket_listener() {}

	void prepare(const netkit::ipap& bind2);

	/*virtual*/ void open() override;
	/*virtual*/ void stop() override;

};


class tcp_listener : public socket_listener
{
	netkit::waitable_socket sock;

protected:
	/*virtual*/ void accept_impl(const netkit::ipap& bind2) override;
	NIXONLY(virtual void kick_socket());

public:

	tcp_listener(loader& ldr, const str::astr& name, const asts& bb);
	/*virtual*/ ~tcp_listener() {}

	/*virtual*/ void close(bool fbc) override
	{
		sock.close(fbc);
	}
};


class udp_listener : public socket_listener
{
	netkit::socket sock;

protected:
	virtual void accept_impl(const netkit::ipap& bind2);

public:

	udp_listener(loader& ldr, const str::astr& name, const asts& bb);
	/*virtual*/ ~udp_listener() {}

	/*virtual*/ void close(bool fbc) override
	{
		sock.close(fbc);
	}

};
