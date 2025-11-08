#pragma once

namespace conn
{
	bool is_valid_addr(const str::astr_view& a_raw); // check string match to {tcp://domain_or_ipv4:port}
	netkit::pipe* connect(netkit::endpoint& addr, netkit::socket_info_func sif);
}

