#include "pch.h"

handler_ss::handler_ss(loader& ldr, listener* owner, const asts& bb) :handler(ldr, owner, bb)
{
	core.load(ldr, owner->name, bb);
}

void handler_ss::on_pipe(netkit::pipe* pipe)
{
	std::thread th(&handler_ss::worker, this, pipe);
	th.detach();
}

void handler_ss::worker(netkit::pipe* raw_pipe)
{
	netkit::pipe_ptr p(raw_pipe);
	netkit::pipe_ptr p_enc(new ss::core::crypto_pipe(p, std::move(core.cb()), core.masterKey, core.cp));

	u8 packet[512];
	signed_t rb = p_enc->recv(packet, -2);
	if (rb != 2)
		return;

	netkit::endpoint ep;
	signed_t len;

	switch (packet[0])
	{
	case 1: // ip4
		rb = p_enc->recv(packet + 2, -3);
		if (rb != 3)
			return;
		ep.set_ip4(*(netkit::ip4*)(packet + 1));
		break;
	case 3: // domain name

		len = packet[1]; // len of domain
		rb = p_enc->recv(packet, -len);
		if (rb != len)
			return;
		ep.set_domain(std::string((const char*)packet, len));
		break;

	case 4: // ipv6
		/* ipv6 not supported yet */
		p_enc->recv(packet+2, -15); // read 15 of 16 bytes of ipv6 address (1st byte already read)

		/// (ipv6 *)(packet+1)
		return;
	}

	rb = p_enc->recv(packet, -2);
	if (rb != 2)
		return;

	signed_t port = ((signed_t)packet[0]) << 8 | packet[1];
	ep.set_port(port);

	if (netkit::pipe_ptr outcon = connect(ep, false))
		bridge(/*ep,*/ std::move(p_enc), std::move(outcon));
}

