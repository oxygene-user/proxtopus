#include "pch.h"

namespace conn
{

	bool is_valid_addr(const std::string_view& a_raw) // check string match to {domain_or_ipv4:port}
	{
		std::string_view a = a_raw;
		if (str::starts_with(a, ASTR("tcp://")))
			a = a.substr(6);

		if (a.find(ASTR("://")) != std::string::npos)
			return false;

		size_t dv = a.find(':');
		if (dv == std::string::npos)
			return false;

		auto dm = a.substr(0, dv);
		if (dm.empty() || dm.find_first_of(" :?") != std::string::npos)
			return false;

		if (dm[0] == '.' || str::get_last_char(dm) == '.')
			return false;

		size_t dmp = dm.rfind('.');
		if (dmp > 0 && dmp != std::string::npos)
		{
			if (is_digit(dm[dmp + 1]))
			{
				// check it ip address
				signed_t cnt = 0;
				for (str::token<char> tkn(dm, '.'); tkn; ++tkn)
				{
					signed_t x = -1;
					auto res = std::from_chars(tkn->data(), tkn->data() + tkn->length(), x);
					if (res.ec == std::errc::invalid_argument || x < 0 || x > 255)
						return false;
					++cnt;
					if (cnt > 4)
						return false;
				}
			}
		}

		auto ports = a.substr(dv + 1);
		signed_t port = 0;
		std::from_chars(ports.data(), ports.data() + ports.length(), port);
		return port > 0;
	}

	netkit::pipe* connect(const netkit::endpoint& addr)
	{
		if (addr.type() == netkit::AT_TCP_DOMAIN)
			addr.get_ip4(true);

		if (addr.type() == netkit::AT_TCP_RESLOVED)
		{

			netkit::tcp_pipe* con = new netkit::tcp_pipe();
			con->set_address(addr);
			if (con->connect())
				return con;
			delete con;
			return nullptr;
		}

		return nullptr;
	}

} // namespace conn
