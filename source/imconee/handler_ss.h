#pragma once

#include "cipher_ss.h"

class handler_ss : public handler // socks4 and socks5
{
	void worker(netkit::pipe* pipe);

	ss::core core;

public:
	handler_ss(loader& ldr, listener* owner, const asts& bb);
	virtual ~handler_ss() { stop(); }

	/*virtual*/ void on_pipe(netkit::pipe* pipe) override;
};

