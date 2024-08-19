#pragma once

#include "netkit.h"
#include "handlers.h"

class loader;
class proxy;

class listener : public netkit::socket
{
protected:
	std::unique_ptr<handler> hand;
public:
	listener(loader& ldr, const str::astr& name, const asts& bb);
	/*virtual*/ ~listener() {}

	virtual void open() = 0;
	virtual void stop() = 0;

	static listener* build(loader& ldr, const str::astr& name, const asts& bb);
};

class tcp_listener : public listener
{
	enum state_stage : u8
	{
		IDLE,
		ACCEPTOR_START,
		ACCEPTOR_WORKS,
	};

	struct statestruct
	{
		netkit::ip4 bind = {};
		u16 port = 0;
		state_stage stage = IDLE;
		bool need_stop = false;
	};

	static_assert( sizeof(statestruct) == 8 );

	spinlock::syncvar<statestruct> state;
	void acceptor();


public:

	tcp_listener(loader& ldr, const str::astr& name, const asts& bb);
	//tcp_listener(handler *h) { hand.reset(h); }
	/*virtual*/ ~tcp_listener() {}

	void prepare(netkit::ip4 bind2, signed_t port);

	/*virtual*/ void open() override;
	/*virtual*/ void stop() override;

};