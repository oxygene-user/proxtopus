#pragma once

namespace conn
{
	bool is_valid_addr(const std::string_view& a_raw); // check string match to {tcp://domain_or_ipv4:port}
	netkit::pipe* connect(const netkit::endpoint& addr);
}

