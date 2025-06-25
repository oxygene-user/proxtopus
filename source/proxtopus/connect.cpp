#include "pch.h"

namespace conn
{

	bool is_valid_addr(const str::astr_view& a_raw) // check string match to {domain_or_ipv4:port}
	{
		str::astr_view a = a_raw;
		if (str::starts_with(a, ASTR("tcp://")))
			a = a.substr(6);

		if (a.find(ASTR("://")) != str::astr::npos)
			return false;

		size_t dv = a.find(':');
		if (dv == str::astr::npos)
			return false;

		auto dm = a.substr(0, dv);
		if (dm.empty() || dm.find_first_of(" :?") != str::astr::npos)
			return false;

		if (dm[0] == '.' || str::get_last_char(dm) == '.')
			return false;

		if (size_t dmp = dm.rfind('.'); dmp > 0 && dmp != str::astr::npos)
		{
			if (is_digit(dm[dmp + 1]))
			{
				// check it ip address
				signed_t cnt = 0;
				enum_tokens_a(tkn, dm, '.')
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

	netkit::pipe* connect(netkit::endpoint& addr)
	{
		if (addr.state() == netkit::EPS_DOMAIN)
			addr.resolve_ip(glb.cfg.ipstack | conf::gip_any | conf::gip_log_it);

		if (addr.state() == netkit::EPS_RESLOVED)
		{
			if (glb.e->is_banned(addr.get_ip()))
			{
				LOG_W("ip address ($) is temporary banned", addr.get_ip().to_string(true));
				return nullptr;
			}

			netkit::tcp_pipe* con = NEW netkit::tcp_pipe();
			con->set_address(addr);

			//if (addr.domain() != "play.google.com")
				//return nullptr;

			if (con->connect())
				return con;
			delete con;
			return nullptr;
		}

		return nullptr;
	}

} // namespace conn
