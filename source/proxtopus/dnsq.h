#pragma once

#include <unordered_set>

class dnspp
{

#pragma pack(push,1)
	struct header
	{
		unsigned      id : 16;		/* identification (used by client for identifications msg) */

		unsigned      rd : 1;       /* resursion desired (DNS server must return IP addr of domain) */
		unsigned      tc : 1;       /* truncated (msg is truncated, usual for UDP protocol) */
		unsigned      aa : 1;       /* authoritative answer */
		unsigned      opcode : 4;   /* operation code( 0 - usual query, 1 - inverse query, 2 - query of server`s status) */
		unsigned      qr : 1;       /* type of msg (0 - query; 1 - response) */

		unsigned      rcode : 4;    /* return code (0 - no errors, 3 - domain name error) */
		unsigned      spare : 3;    /* not used, must be zero */
		unsigned      ra : 1;       /* resursion avaiable (does DNS server support recursion) */

		unsigned      nques : 16;   /* number of questions */
		unsigned      nansw : 16;   /* number of answers */
		unsigned      nauth : 16;   /* number of authorities */
		unsigned      nainf : 16;   /* number of additional informations */
	};

#pragma pack(pop)

	static_assert( sizeof(header) == 12 );

public:
	enum constanta
	{
		rfc_hostname_size = 256,	// max size of host domain name by RFC 1034
		iplist_size = 4,            // max size of server`s list
		max_buf_size = 1500,
		prebuffer = 32,
		request_size = 512,
		header_size = sizeof(header),
		maximum_cnames = 8,
		maximum_fails = 8,
	};
private:

	std::array<u8, rfc_hostname_size> rname;        // current raw name of host

public:

	dnspp();
	~dnspp();

	enum qtype : u16
	{
		qtype_a = 1,		// IP address
		qtype_aaaa = 28,    // IPv6 address
		qtype_ns = 2,       // DNS server
		qtype_cname = 5,    // alias name
		qtype_soa = 6,      // soa
		qtype_ptr = 12,     // full domain name
		qtype_hinfo = 13,   // host info
		//qtype_mx = 15,      // mail exchange
		//qtype_axfr = 252,   // zone transmit
		qtype_opt = 41,     // EDNS opt
		qtype_any = 255,    // all
	};

	enum qclass : u16
	{
		qclass_inet = 1,    // internet addresses
	};

	enum parse_result
	{
		parse_ok,
		parse_done,
		parse_empty,
		parse_data_error,
		parse_message_trunc,
		parse_server_error,
		parse_name_not_found,
		parse_unimplemented_error,

	};

	struct parser
	{
		netkit::pgen pg;

		signed_t psize[3];

		signed_t ttl = 0;
		str::astr host;
		str::astr cname;
		qtype ty = qtype_any;
		u8 part = 0; // parsing part: 0, 1, 2

		parser(u8* packet) :pg(packet, dnspp::request_size, dnspp::prebuffer) {}

		parse_result start();
		parse_result next();

	};

	static u16 packet_id(const u8* data);

	bool prepare(const str::astr_view& hn);
	bool build_query(qtype qt, netkit::pgen& pg);

};

class dns_resolver
{
	struct cache_rec : public ptr::sync_shared_object
	{
		signed_t ttl = 0;
		time_t decaytime = 0;
		using ipsar = std::vector<netkit::ipap>;
		spinlock::syncvar<ipsar> ips;
		cache_rec(signed_t sec):ttl(sec)
		{
			decaytime = chrono::now() + sec;
		}
		cache_rec(ipsar &&ar) {
			ips.lock_write()() = std::move(ar);
		}
		cache_rec(const netkit::ipap& ip) {
			ips.lock_write()().push_back(ip);
		}
		cache_rec() {}
		~cache_rec()
		{
			ips.lock_write()().clear();
		}
		static void add_ip(ipsar &ar, const netkit::ipap& ip)
		{
			for (netkit::ipap& a : ar)
				if (a.copmpare_a(ip))
					return;
			ar.push_back(ip);
		}
		bool add_ip(cache_rec& rec)
		{
			if (&rec == this)
				return false;

			auto cpy = std::move(rec.ips.lock_write()());
			auto ar = ips.lock_write();
			for (netkit::ipap& a : cpy)
				cache_rec::add_ip(ar(), a);
			return true;
		}


		bool is_empty() const
		{
			return ips.lock_read()().size() == 0;
		}

		str::astr to_string(bool with_port) const
		{
			str::astr s;
			auto ar = ips.lock_read();
			for (const netkit::ipap& ip : ar())
			{
				if (!s.empty())
					s.push_back('|');
				s.append(ip.to_string(with_port));
			}
			return s;
		}

		netkit::ipap get_one(signed_t rindex) const
		{
			auto ar = ips.lock_read();

			signed_t cnt = ar().size();
			if (cnt == 0)
				return netkit::ipap();

			signed_t index = rindex % cnt;
			signed_t i = index;
			signed_t iv4 = -1;
			signed_t iv6 = -1;
			for (;;)
			{
				const netkit::ipap& ip = ar()[i];
				if ((glb.cfg.ipstack == conf::gip_only4 || glb.cfg.ipstack == conf::gip_prior4) && ip.v4)
					return ip;

				if ((glb.cfg.ipstack == conf::gip_only6 || glb.cfg.ipstack == conf::gip_prior6) && !ip.v4)
					return ip;

				if (ip.v4 && iv4 < 0)
					iv4 = i;

				if (!ip.v4 && iv6 < 0)
					iv6 = i;

				++i;
				if (i >= cnt)
					i = 0;
				if (i == index)
					break;
			}

			if (glb.cfg.ipstack == conf::gip_only4 && iv4 < 0)
				return netkit::ipap();
			if (glb.cfg.ipstack == conf::gip_only6 && iv6 < 0)
				return netkit::ipap();

			if (iv4 >= 0)
				return ar()[iv4];

			if (iv6 >= 0)
				return ar()[iv6];

			return netkit::ipap();
		}
	};
	struct resolve_rec
	{
		str::astr hn;
		std::mutex mut;
		std::condition_variable cv;
		signed_t tid;
	};

	struct cachemap : public tools::shashmap<char, ptr::shared_ptr<cache_rec>>
	{
		void set(const str::astr& h, ptr::shared_ptr<cache_rec>& p)
		{
			auto x = insert(std::pair(h,p));
			if (x.second)
				return;

			if (x.first->second->add_ip(*p))
				p = x.first->second; // replace cache_rec in p to old one
		}
		void set(const str::astr_view& h, ptr::shared_ptr<cache_rec>& p)
		{
			auto x = insert(std::pair(h, p));
			if (x.second)
				return;

			if (x.first->second->add_ip(*p))
				p = x.first->second; // replace cache_rec in p to old one
		}
	};

	struct newns // new name server
	{
		str::shared_str::ptr name;
		str::astr zone;
		cache_rec::ipsar ips;
		signed_t ttl = 0;

		newns() {}

		void init(const str::shared_str::ptr& name1, str::astr&& zone1, signed_t ttl1) {
			name = name1;
			zone = std::move(zone1);
			ttl = ttl1;
		}
	};

	struct nameserver : ptr::sync_shared_object
	{
		str::shared_str::ptr name;
		netkit::ipap ip;
		const proxy* prx = nullptr;
		time_t decaytime = 0; // 0 - infinity life
		std::atomic<signed_t> failcount = 0;
		nameserver(const str::shared_str::ptr& name, const netkit::ipap& ip_) :name(name), ip(ip_) { if (ip.port == 0) ip.port = 53; }
		nameserver(const str::shared_str::ptr& name) :name(name) {}
		bool ip_not_set() const { return ip.port == 0; }
	};

	struct zone;
	using servers_array = std::vector<ptr::shared_ptr<nameserver>>;
	using zones_array = std::vector<std::unique_ptr<zone>>;  // TODO : sort and binary search

	struct zone
	{
		str::astr z;
		zone* parent = nullptr;
		servers_array servers;
		zones_array subs;  // TODO : sort and binary search
		zone(const str::astr_view& z, zone* parent) :z(z), parent(parent)
		{
		}
		signed_t count(const str::astr_view& name) const
		{
			signed_t cnt = 0;
			for (auto& s : servers)
				if (s->name->equals(name))
					++cnt;
			return cnt;
		}

	};

	spinlock::syncvar<cachemap> cache;
	spinlock::syncvar<std::vector<std::unique_ptr<resolve_rec>>> resolving;
	spinlock::syncvar<servers_array> servers;
	spinlock::syncvar<zones_array> zones; // TODO : sort and binary search
	std::atomic<signed_t> rndindex = 0;

	void add_zone_ns(time_t ct, zones_array* zar, newns& ns, const str::astr_view& zonedom, zone *parent, const proxy *prx);
	ptr::shared_ptr<cache_rec> start_resolving(const str::astr& hn);
	void done_resolve(const str::astr hns[], signed_t hnsn);
	ptr::shared_ptr<cache_rec> empty_result(const str::astr hns[], signed_t hnsn);

	struct udp_transport : public netkit::thread_storage, netkit::udp_pipe
	{
		struct proxy_pipe_data
		{
			const proxy* prx = nullptr;
			std::unique_ptr<netkit::udp_pipe> pip;
			proxy_pipe_data(const proxy* p) :prx(p) {}
		};

		std::vector<proxy_pipe_data> ppipes;
		/*virtual*/ netkit::io_result send(const netkit::endpoint& toaddr, const netkit::pgen& pg) override;
		/*virtual*/ netkit::io_result recv(netkit::ipap& from, netkit::pgen& pg, signed_t max_bufer_size) override;
	};

	struct query_internals : public udp_transport
	{
		std::array<str::astr, dnspp::maximum_cnames> hns;
		std::array<ptr::shared_ptr<nameserver>, dnspp::maximum_fails> ns;
		signed_t hn_count = 1, rindex;
		signed_t used_ips = 0; // actual count of items in ns array
		ptr::shared_ptr<nameserver> last_ns;
		std::unordered_set< str::astr > pairs;
		time_t ct = chrono::now();

		udp_transport * transport_override = nullptr;

		enum {
			r_ok,
			r_label2long,
			r_request2big,
			r_2manycnames,
			r_notresolved,
			r_networkfail,
		} result = r_ok;

		query_internals(const str::astr_view& hn, bool casedn = true)
		{
			hns[0] = hn;
			if (casedn)
			{
				for (char* c = hns[0].data(), *e = hns[0].data() + hns[0].length(); c < e; ++c)
				{
					char ch = *c;
					if (ch >= 'A' && ch <= 'Z')
					{
						*c = ch + 32;
					}
				}
			}
		}

		netkit::io_result query(netkit::pgen& pg /* in/out*/);

		bool checktime(time_t decaytime) const
		{
			return decaytime == 0 || ct < decaytime;
		};

		const str::astr& cur_host() const
		{
			return hns[hn_count - 1];
		}
		str::astr pairkey(const netkit::ipap& nsip) const
		{
			auto s = cur_host();
			s.push_back('|');
			s.append((const char*)&nsip, nsip.v4 ? sizeof(netkit::ipap::ipv4) : sizeof(netkit::ipap::ipv6));
			return s;
		}
		bool already(const netkit::ipap &nsip) const
		{
			return pairs.contains(pairkey(nsip));
		}
		void on_success_request()
		{
			--used_ips; // current dns server is ok, remove it from exclude list

			// store pair host/ns
			if (last_ns)
				pairs.emplace(pairkey(last_ns->ip));
		}
	};

	ptr::shared_ptr<cache_rec> shnr(query_internals& qi);
	bool find_ns(query_internals& qi, signed_t deep);
	static bool find_and_add(zones_array* za, nameserver* ns, const cache_rec* ips);
	void add_zone_ns_ip(nameserver* ns, const cache_rec* ips); // removes ns from zone and adds ips to same zone
	ptr::shared_ptr<cache_rec> resolve(query_internals &qi, bool lock_resolving);

public:

	dns_resolver(bool parse_hosts);
	
	netkit::ipap resolve(const str::astr &hn, bool log_it);
	void load_serves(engine *e, const asts* s);
};