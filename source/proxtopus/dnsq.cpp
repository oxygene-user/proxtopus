#include "pch.h"

#ifdef _WIN32
#pragma comment(lib, "shell32.lib")
#include <shlobj.h>
#endif // _WIN32

#define ONLYIPV4 (glb.cfg.ipstack == conf::gip_only4)
#define ONLYIPV6 (glb.cfg.ipstack == conf::gip_only6)
#define ALLOWIPV4 (glb.cfg.ipstack != conf::gip_only6)
#define ALLOWIPV6 (glb.cfg.ipstack != conf::gip_only4)

dnspp::dnspp()
{
}

dnspp::~dnspp()
{
}


bool dnspp::prepare(const str::astr_view& hn)
{
	if (hn.length() >= rname.size() - 1)
	{
		rname[0] = 0;
		return false;
	}

	signed_t pos = 0;
	signed_t len = 0;
	signed_t i, hnl = hn.length();
	for (i = 0; i < hnl; ++i)
	{
		if (hn[i] == '.')
		{
			signed_t ll = i - len;
			if (ll > 63)
			{
				rname[0] = 0;
				return false;
			}
			rname[pos++] = tools::as_byte(ll);
			for (; len < i; ++len) {
				rname[pos++] = hn[len];
			}
			++len;
		}
	}
	signed_t ll = i - len;
	if (ll > 63)
	{
		rname[0] = 0;
		return false;
	}
	rname[pos++] = tools::as_byte(ll);
	for (; len < i; ++len) {
		rname[pos++] = hn[len];
	}
	rname[pos] = 0;
	return true;
}

bool dnspp::build_query(qtype qt, netkit::pgen& pg)
{
	pg.set_extra(32); // always keep 32 bytes pre-buffer for udp proxy
	pg.start();
	pg.sz = dnspp::request_size;

	signed_t len = strlen((const char *)rname.data()) + 1;        /* + 1 to include zero byte too */
	signed_t size = sizeof(header) + len + (sizeof(u16) * 2);

	if (size > pg.sz)
		return false;

	header& mh = pg.pushstruct<header>();

	mh.id = netkit::to_ne16(spinlock::tid_self() >> 4);
	mh.rd = 1; // recursion
	mh.nques = netkit::to_ne(1);

	pg.pusha( rname.data(), len ); // qname
	pg.push16(qt); // qtype
	pg.push16(qclass_inet); // qclass

	pg.sz = pg.ptr;
	return true;
}

static bool skip_dns_string(netkit::pgen& pg, signed_t lim = -1) // skip and check. returns false if string is corrupted
{
	signed_t p = pg.ptr, slen = 0;
	if (p >= pg.sz)
		return false;
	if (lim < 0)
		lim = p;

	for (;;)
	{
		u8 x = pg.get<u8>();
		if (x == 0)
			return slen < dnspp::rfc_hostname_size;

		if ((x >= 0x40 && x <= 0xbf) || pg.ptr == pg.sz)
			return false;

		if (x >= 0xc0)
		{
			signed_t new_ptr = ((signed_t)(x & 0x3F)) << 8;
			new_ptr |= pg.get<u8>();

			if (new_ptr < dnspp::header_size || new_ptr >= lim)
				return false;

			lim = new_ptr;

			u16 keep_ptr = pg.ptr;
			pg.ptr = tools::as_word(new_ptr);
			if (!skip_dns_string(pg, lim))
				return false;
			slen += pg.ptr - new_ptr;
			if (slen >= dnspp::rfc_hostname_size)
				return false;
			pg.ptr = keep_ptr;
			return true;
		}
		else
		{
			if (slen > 0) ++slen; // dot
			slen += x;
			if (!pg.skipn(x))
				return false;
			if (slen >= dnspp::rfc_hostname_size)
				return false;
		}
	}

	UNREACHABLE();
};

static bool extract_dns_string(str::astr &s, netkit::pgen& pg, signed_t lim = -1) // skip and check. returns false if string is corrupted
{
	signed_t p = pg.ptr;
	if (p >= pg.sz)
		return false;

	if (lim < 0)
		lim = p;

	for (;;)
	{
		u8 x = pg.get<u8>();
		if (x == 0)
			return s.length() < dnspp::rfc_hostname_size;

		if ((x >= 0x40 && x <= 0xbf) || pg.ptr == pg.sz)
			return false;

		if (x >= 0xc0)
		{
			signed_t new_ptr = ((signed_t)(x & 0x3F)) << 8;
			new_ptr |= pg.get<u8>();

			if (new_ptr < dnspp::header_size || new_ptr >= lim)
				return false;

			lim = new_ptr;

			u16 keep_ptr = pg.ptr;
			pg.ptr = tools::as_word(new_ptr);
			if (!extract_dns_string(s, pg, lim))
				return false;
			pg.ptr = keep_ptr;
			return true;
		}
		else
		{
			if (!s.empty())
				s.push_back('.');
			s.append(pg.str_view(x));

			if (s.length() >= dnspp::rfc_hostname_size)
				return false;

			if (!pg.skipn(x))
				return false;
		}
	}

	UNREACHABLE();
};

u16 dnspp::packet_id(const u8* data)
{
	const header* hdr = (const header *)data;
	return netkit::to_he16(hdr->id);
}

dnspp::parse_result dnspp::parser::start()
{
	pg.start();
	const header* hdr = pg.readstruct<header>();

	if (nullptr == hdr)
		return parse_data_error;
	if (netkit::to_he16(hdr->id) != ((spinlock::tid_self() >> 4) & 0xffff))
		return parse_data_error;
	if (!hdr->qr)
		return parse_data_error;
	//if (hdr->tc)
		//return parse_message_trunc;
	if (hdr->rcode == 2 || hdr->rcode == 4 || hdr->rcode == 5)
		return parse_server_error;
	if (hdr->rcode == 3)
		return parse_name_not_found;
	signed_t nques = netkit::to_he16(hdr->nques);
	psize[0] = netkit::to_he16(hdr->nansw);
	psize[1] = netkit::to_he16(hdr->nauth);
	psize[2] = netkit::to_he16(hdr->nainf);

	if (psize[0] == 0 && psize[1] == 0 && psize[2] == 0)
		return parse_empty;

	// skip query info
	for (signed_t i = 0; i < nques; ++i)
	{
		if (!skip_dns_string(pg))
			return parse_data_error;
		if (!pg.skipn(4)) // skip 4 bytes (qtype and qclass)
			return parse_data_error;
	}
	part = 0;
	return next();
}

dnspp::parse_result dnspp::parser::next()
{
	while (psize[part] == 0)
	{
		++part;
		if (part == 3)
			return parse_done;
	}

	host.clear();
	if (!extract_dns_string(host, pg))
		return parse_data_error;

	if (!pg.enough(2 + 2 + 4 + 2)) // TYPE(2), CLASS(2), TTL(4), RDLENGTH(2)
		return parse_data_error;

	ty = (qtype)pg.read16();
	qclass cl = (qclass)pg.read16();

	if (ty != qtype_opt && cl != qclass_inet)
		return parse_data_error;

	ttl = pg.read32();
	u16 rdlen = pg.read16();

	if (!pg.enough(rdlen))
		return parse_data_error;

	if (ty == qtype_cname || ty == qtype_ns)
	{
		cname.clear();
		if (!extract_dns_string(cname, pg))
			return parse_data_error;

	}
	else
	{
		cname = str::astr_view((const char*)pg.raw(), rdlen);
		pg.skipn(rdlen);
	}

#if 0
		if (t == dnspp::qtype_soa)
		{
			cname.clear();
			if (!extract_dns_string(cname, pg))
				return parse_data_error;
			if (!skip_dns_string(pg))
				return parse_data_error;
			/*u32 serial =*/ pg.read32();
			/*u32 refresh =*/ pg.read32();
			/*u32 retry =*/ pg.read32();
			/*u32 expire =*/ pg.read32();
			/*u32 minimum =*/ pg.read32();

			answs.emplace_back(aname, cname, ttl, t);
			some_answs = true;
			return parse_ok_soa;
		}
#endif

	--psize[part];

	if (ty == qtype_opt)
		return next();

	return parse_ok;
}

dns_resolver::dns_resolver(bool parse_hosts)
{
	if (parse_hosts)
	{
#ifdef _WIN32
		FN hfn(MAX_PATH, 0);
		if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_SYSTEM | CSIDL_FLAG_CREATE, nullptr, 0, hfn.data())))
		{
			hfn.resize(fnlen(hfn));
			path_append(hfn, MAKEFN("drivers\\etc\\hosts"));
		}
		else
		{
			hfn.clear();
		}
#endif
#ifdef _NIX
		FN hfn(MAKEFN("/etc/hosts"));
#endif

		if (hfn.length() > 0)
		{
			buffer b;
			load_buf(hfn, b);

			for (str::token<char, str::sep_line<char>> t((const char*)b.data(), b.size()); t; t())
			{
				auto ln = str::trim(*t);
				if (ln.length() == 0 || ln[0] == '#')
					continue;

				netkit::ipap ip;
				ptr::shared_ptr<cache_rec> rec;
				for (str::token<char, str::sep_hollow<char>> lt(ln); lt; lt())
				{
					if (!rec)
					{
						ip = netkit::ipap::parse(*lt, false);
						if (ONLYIPV4 && !ip.v4)
							break;
						if (ONLYIPV6 && ip.v4)
							break;

						rec = NEW cache_rec(ip);
						continue;
					}

					auto w = cache.lock_write();
					w().set(*lt, rec);
				}

			}

		}
	}
}

void dns_resolver::done_resolve(const str::astr hns[], signed_t hn_count)
{
	signed_t checked = 0;
	const signed_t full = ((signed_t)1 << hn_count) - 1;

	for (; checked != full;)
	{
		bool restart = false;
		auto rslv = resolving.lock_write();
		for (signed_t i = (signed_t)rslv().size() - 1; i >= 0; --i)
		{
			std::unique_ptr<resolve_rec>& rr = rslv()[i];
			if (rr->hn.empty())
				continue;

			for (signed_t j = 0; j < hn_count; ++j)
			{
				if (0 != (checked & ((signed_t)1 << j)))
					continue;

				if (rr->hn == hns[j])
				{
					checked |= (signed_t)1 << j;
					rr->hn.clear();
					std::lock_guard<std::mutex> m(rr->mut);
					rslv.unlock();

					rr->cv.notify_all();
					restart = true;
					break;
				}
			}
			if (restart)
				break;
		}
		if (!restart)
			break;
	}
}

bool dns_resolver::find_and_add(zones_array* za, nameserver* ns, const cache_rec* ips)
{
	for (auto& z : *za)
	{
		for (signed_t i=z->servers.size()-1;i>=0;--i)
		{
			auto& s = z->servers[i];
			if (s.get() == ns)
			{
				ASSERT(z->count(ns->name->cstr()) == 1);
				if (ips)
				{
					bool first = true;
					for (const netkit::ipap& ip : ips->ips.lock_read()())
					{
						if (first)
						{
							ns->ip = ip;
							first = false;
							continue;
						}

						nameserver* nns = NEW nameserver(ns->name, ip);
						nns->prx = ns->prx;
						nns->decaytime = ns->decaytime;
						z->servers.emplace_back(nns);
					}
				}
				else
				{
					tools::remove_fast(z->servers, i);
				}
				return true;
			}
		}
		if (find_and_add(&z->subs, ns, ips))
			return true;
	}
	return false;
}

void dns_resolver::add_zone_ns_ip(nameserver* ns, const cache_rec* ips)
{
	auto zs = zones.lock_write();
	find_and_add( &zs(), ns, ips );
}

ptr::shared_ptr<dns_resolver::cache_rec> dns_resolver::shnr(query_internals& qi)
{
	ptr::shared_ptr<cache_rec> rec = NEW cache_rec(qi.ns[qi.used_ips-1]->ip);
	return rec;
}

bool dns_resolver::find_ns(query_internals& qi, signed_t deep)
{
	auto usable = [&](const nameserver* ns) -> bool
	{
		if (!qi.checktime(ns->decaytime))
			return false;

		if (qi.already(ns->ip))
			return false;

		if (ns->ip_not_set())
			return true;

		if (ns->ip.v4 && ONLYIPV6)
			return false;
		if (!ns->ip.v4 && ONLYIPV4)
			return false;

		if (qi.used_ips != 0)
		{
			for (signed_t i = 0; i < qi.used_ips; ++i)
			{
				if (qi.ns[i]->ip.copmpare_a(ns->ip))
					return false;
			}
		}

		return true;
	};

//	if (deep > 10)
//		__debugbreak();

	auto zs = zones.lock_read();

	const zones_array* curza = &zs();
	const zone* curz = nullptr;

	for (str::token<char, str::sep_onechar_rev<char, '.'>> t(qi.host); t; t())
	{
		bool swlv = false;
		for (const auto& z : *curza)
		{
			if (z->z == *t)
			{
				curz = z.get();
				curza = &z->subs;
				swlv = true;
				break;
			}
		}
		if (swlv && !t.remaind().empty())
			continue;

		bool do_parent = false;
		while (curz)
		{
			while (curz != nullptr && (do_parent || (curz->servers.size() == 0 && curz->parent !=nullptr)))
			{
				// no servers in this zone
				// return to parent zone
				curz = curz->parent;
				do_parent = false;
			}

			if (curz != nullptr && curz->servers.size() != 0)
			{
				signed_t index = qi.rindex % curz->servers.size();
				signed_t i = index;
				for (signed_t cnt = curz->servers.size();;)
				{
					auto ns = curz->servers[i];
					if (usable(ns.get()))
					{
						bool samehostandresolver = ns->name->equals(qi.host);

						if (ns->ip_not_set())
						{
							ASSERT(!samehostandresolver);

							zs.unlock();

							DL(DLCH_DNS, "select resolver for %s : %s (no ip)", qi.host.c_str(), ns->name->to_string().c_str());

							for (signed_t tcount = 3; tcount >= 0; --tcount)
							{
								query_internals qi2(ns->name->cstr(), false);
								qi2.rindex = rndindex++;
								for(signed_t j = 0; j< qi.used_ips; ++j)
									qi2.ns[j] = qi.ns[j];
								qi2.used_ips = qi.used_ips;
								qi2.transport_override = qi.transport_override;
								if (qi2.transport_override == nullptr)
									qi2.transport_override = &qi;

								// need resolve
								auto rr = resolve(qi2, false);

								auto ips = rr->ips.lock_write();
								for (netkit::ipap& ip : ips())
									ip.port = 53;
								ips.unlock();

								if (qi2.result == query_internals::r_ok)
								{
									add_zone_ns_ip( ns.get(), rr.get() );
									break;
								}
								else
								{
									if (tcount > 0)
										continue;

									DL(DLCH_DNS, "can't resolve resolver's ip (%s)", ns->name->to_string().c_str());
									add_zone_ns_ip(ns.get(), nullptr);
									break;
								}
							}
							return find_ns(qi, deep + 1);
						}

						qi.ns[qi.used_ips++] = ns;
						qi.last_ns = ns;
						zs.unlock();

						DL(DLCH_DNS, "select resolver for %s : %s (%s)", qi.host.c_str(), ns->name->to_string().c_str(), ns->ip.to_string(true).c_str());
						return samehostandresolver;
					}

					++i;
					if (i >= cnt)
						i = 0;
					if (i == index)
					{
						do_parent = true;
						break;
					}
				}
			}
			if (!do_parent)
				break;
		}

		break;
	}

	zs.unlock();

	auto se = servers.lock_read();
	for (const auto &x : se())
	{
		if (usable(x.get()))
		{
			qi.ns[qi.used_ips++] = x;
			qi.last_ns = x;
			return false;
		}
	}
	se.unlock();

	qi.last_ns = nullptr;
	return false;
}

void dns_resolver::add_zone_ns(time_t ct, zones_array* zar, newns& ns, const str::astr_view& zone_dom, zone* parent, const proxy* prx)
{
	str::token<char, str::sep_onechar_rev<char, '.'>> t(zone_dom);

	for (const auto& z : *zar)
	{
		if (z->z == *t)
		{
			if (!t.remaind().empty())
			{
				add_zone_ns(ct, &z->subs, ns, t.remaind(), z.get(), prx);
				return;
			}

			str::shared_str::ptr found;
			for (signed_t i = z->servers.size() - 1; i >= 0; --i)
			{
				nameserver* s = z->servers[i];
				if (s->decaytime != 0 && ct >= s->decaytime)
				{
					tools::remove_fast(z->servers, i);
					continue;
				}

				if (s->name->equals(ns.name))
				{
					ns.name = s->name;
					if (!found)
						found = s->name;

					for (signed_t j = ns.ips.size() - 1; j >= 0; --j)
					{
						if (s->ip_not_set())
						{
							s->ip = ns.ips[j];
						rmv:
							tools::remove_fast(ns.ips, j);
							if (ns.ips.empty())
								return; // all ip's already present with same name
						} else if (ns.ips[j].copmpare_a(s->ip))
							goto rmv; // do you like goto's?
					}
				}
			}

			str::shared_str::ptr nm = found;
			if (!nm) nm = ns.name;
			for (auto& ip : ns.ips)
			{
				nameserver* nns = NEW nameserver(nm, ip);
				nns->prx = prx;
				nns->decaytime = ct + ns.ttl;
				z->servers.emplace_back(nns);
				DL(DLCH_DNS, "add zone ns %s (\"%s\") with ip: %s", ns.name->to_string().c_str(), ns.zone.c_str(), ip.to_string(false).c_str());
			}
			if (ns.ips.empty() && !found)
			{
				nameserver* nns = NEW nameserver(nm);
				nns->prx = prx;
				nns->decaytime = ct + ns.ttl;
				z->servers.emplace_back(nns);
				DL(DLCH_DNS, "add zone ns (\"%s\") unresolved for now: %s", ns.zone.c_str(), ns.name->to_string().c_str());
			}

			return;
		}
	}

	// add zone
	zar->push_back( std::make_unique<zone>(*t, parent) );
	zone* a = (*zar)[zar->size() - 1].get();
	if (!t.remaind().empty())
	{
		add_zone_ns(ct, &a->subs, ns, t.remaind(), a, prx);
		return;
	}

	str::shared_str::ptr nm = ns.name;
	for (auto& ip : ns.ips)
	{
		nameserver* nns = NEW nameserver(nm, ip);
		nns->prx = prx;
		nns->decaytime = ct + ns.ttl;
		a->servers.emplace_back(nns);
		DL(DLCH_DNS, "new zone ns %s (\"%s\") with ip: %s", ns.name->to_string().c_str(), ns.zone.c_str(), ip.to_string(false).c_str());
	}
	if (ns.ips.empty())
	{
		nameserver* nns = NEW nameserver(nm);
		nns->prx = prx;
		nns->decaytime = ct + ns.ttl;
		a->servers.emplace_back(nns);
		DL(DLCH_DNS, "new zone ns (\"%s\") unresolved for now: %s", ns.zone.c_str(), ns.name->to_string().c_str());
	}

};

ptr::shared_ptr<dns_resolver::cache_rec> dns_resolver::empty_result(const str::astr hns[], signed_t hnsn)
{
	auto cw = cache.lock_write();
	cache_rec* cre = NEW cache_rec(1);
	ptr::shared_ptr<cache_rec> p(cre);
	for( signed_t i=0; i<hnsn; ++i )
		cw()[hns[i]] = cre;
	cw.unlock();
	return p;
}


ptr::shared_ptr<dns_resolver::cache_rec> dns_resolver::start_resolving(const str::astr& hn)
{
	auto rslv = resolving.lock_write();
	resolve_rec* emptyrr = nullptr;
	for (signed_t i = (signed_t)rslv().size() - 1; i >= 0; --i)
	{
		std::unique_ptr<resolve_rec>& rr = rslv()[i];

		if (rr->hn.empty())
		{
			if (!emptyrr)
			{
				tools::remove_fast(rslv(), i);
				continue;
			}

			emptyrr = rr.get();
			continue;
		}

		if (rr->hn == hn)
		{
			{
				std::unique_lock<std::mutex> m(rr->mut);
				rslv.unlock();
				// just wait
				rr->cv.wait(m);
			}
			// now cache contains this entry

			auto cr = cache.lock_read();
			const auto ce1 = cr().find(hn);
			if (ce1 != cr().end())
			{
				return ce1->second;
			}
			cr.unlock();

#ifdef _DEBUG
			DEBUGBREAK();
#endif
			return empty_result(&hn, 1);
		}
	}
	if (emptyrr == nullptr)
	{
		emptyrr = NEW resolve_rec();
		rslv().emplace_back(emptyrr);
	}

	emptyrr->tid = spinlock::tid_self();
	emptyrr->hn = hn;

	rslv.unlock();

	return ptr::shared_ptr<cache_rec>();
}

netkit::ipap dns_resolver::resolve(const str::astr& hn_, bool log_it)
{
	netkit::ipap temp = netkit::ipap::parse(str::view(hn_), false);
	if (!temp.is_wildcard())
		return temp;

	query_internals qi( hn_ );
	qi.rindex = rndindex++;

	auto r = resolve(qi, true);
	switch (qi.result)
	{
	case query_internals::r_ok:
		return r->get_one(qi.rindex);
	case query_internals::r_label2long:
		if (log_it)
			LOG_E("dns: name not legal (label too long): %s", qi.host.c_str());
		break;
	case query_internals::r_request2big:
		if (log_it)
			LOG_E("dns: request too big: %s", qi.host.c_str());
		break;
	case query_internals::r_2manycnames:
		if (log_it)
			LOG_E("dns: resolve failed for domain %s (too many cnames)", qi.cnames[0].c_str());
		break;
	case query_internals::r_notresolved:
		if (log_it)
			LOG_E("dns: name not found [%s]", qi.host.c_str());
		break;
	case query_internals::r_networkfail:
		if (log_it)
			LOG_E("dns: all request attempts have been exhausted (network problems?) [%s]", qi.host.c_str());
		break;
	}

	DL(DLCH_DNS, "query failed \"%s\"", qi.cnames[0].c_str());

	return netkit::ipap();
}


ptr::shared_ptr<dns_resolver::cache_rec> dns_resolver::resolve(query_internals &qi, bool lock_resolving)
{
	qi.result = query_internals::r_ok;

	auto cr = cache.lock_read();
	const auto ce = cr().find(qi.host);
	if (ce != cr().end() && qi.checktime(ce->second.get()->decaytime))
	{
		if (ce->second->is_empty())
		{
			if ((ce->second.get()->decaytime - qi.ct) <= 1)
				return ce->second;
		} else
			return ce->second;
	}
	cr.unlock();

	if (lock_resolving)
	{
		DL(DLCH_DNS, "query \"%s\"", qi.host.c_str());

		if (auto p = start_resolving(qi.host))
			return p;
	}

	u8* packet = (u8*)alloca(dnspp::max_buf_size + dnspp::prebuffer);
	dnspp::parser parser(packet + dnspp::prebuffer);

	auto not_resolved = [&](auto ri)
	{
		auto r = empty_result(qi.cnames.data(), qi.cnames_cnt);
		done_resolve(qi.cnames.data(), qi.cnames_cnt);
		qi.result = ri;
		return r;
	};

	dnspp dns;
	if (!dns.prepare(qi.host))
	{
		return not_resolved(query_internals::r_label2long);
	}

	if (find_ns(qi, 0))
		return shnr(qi);

	if (!qi.last_ns)
		return not_resolved(query_internals::r_notresolved);

	bool another_ip = false;

	dnspp::qtype last_query_qtype = dnspp::qtype_a;
	if (ONLYIPV6 || glb.cfg.ipstack == conf::gip_prior6)
		last_query_qtype = dnspp::qtype_aaaa;

	if (!dns.build_query(last_query_qtype, parser.pg))
		return not_resolved(query_internals::r_request2big);

	std::array<newns, 32> nns;

	for (;;)
	{
	next_try:

		ptr::shared_ptr<cache_rec> rec;

		auto rec_prepare = [&]()
			{
				if (rec.get() == nullptr)
					rec = NEW cache_rec(parser.ttl);
				else {
					if (rec->ttl < parser.ttl)
					{
						rec->ttl = parser.ttl;
						rec->decaytime = qi.ct + parser.ttl;
					}
				}
			};

		DL(DLCH_DNS, "query: %s ? %s (%s)", qi.host.c_str(), qi.last_ns->name->to_string().c_str(), qi.ns[qi.used_ips - 1]->ip.to_string(true).c_str());

		for (signed_t tcount = 3; tcount >= 0; --tcount)
		{
			if (netkit::ior_ok == qi.query(parser.pg))
			{
				qi.last_ns->failcount = 0;
				break;
			}
			if (tcount > 0)
				continue;

			DL(DLCH_DNS, "query failed: %s ? %s (%s)", qi.host.c_str(), qi.last_ns->name->to_string().c_str(), qi.ns[qi.used_ips - 1]->ip.to_string(true).c_str());
			++qi.last_ns->failcount;

			if (find_ns(qi, 0))
				return shnr(qi);

			if (!qi.last_ns)
				return not_resolved(query_internals::r_notresolved);

			if (!dns.build_query(last_query_qtype, parser.pg))
				return not_resolved(query_internals::r_request2big);

			goto next_try; // break; and continue;
		}

		qi.ct = chrono::now();

		signed_t nns_count = 0;

		dnspp::parse_result pr;
		bool empty_answer = false;
		for (pr = parser.start(); pr == dnspp::parse_ok; pr = parser.next())
		{
			switch (parser.ty)
			{
			case dnspp::qtype_ns:

				if (ASSERT(nns_count < (signed_t)nns.size()))
				{
					nns[nns_count].ips.clear();
					nns[nns_count++].init(str::shared_str::build(str::view(parser.cname)), std::move(parser.host), parser.ttl);
				}
				continue;
			case dnspp::qtype_cname:

				if ((parser.host == qi.host || qi.has_cname(parser.host)) && !qi.has_cname(parser.cname))
				{
					rec_prepare();
					qi.add_cname(parser.cname);

					DL(DLCH_DNS, "cname: %s -> %s", qi.host.c_str(), parser.cname.c_str());

					auto cw = cache.lock_write();
					cw().set(qi.host, rec);
					cw().set(parser.cname, rec);
				}
				else
				{
					if (qi.has_unchecked_cname())
					{
						rec_prepare();
					}
				}

				continue;
			case dnspp::qtype_a:

				if (ONLYIPV6)
					continue;

				if (parser.host == qi.host)
				{
					if (ASSERT(parser.cname.length() == 4))
					{
						rec_prepare();
						cache_rec::add_ip(rec->ips.lock_write()(), netkit::ipap::build((const u8*)parser.cname.data(), 4, 0));

						auto cw = cache.lock_write();
						cw().set(qi.host, rec);
					}
					continue;
				}

				if (parser.cname.length() == 4)
				{
					bool ns = false;
					for (signed_t ni = 0; ni < nns_count; ++ni)
					{
						newns& n = nns[ni];
						if (n.name->equals(parser.host))
						{
							netkit::ipap ip = netkit::ipap::build((const u8*)parser.cname.data(), 4, 53);
							cache_rec::add_ip(n.ips, ip);
							ns = true;
							break;
						}
					}

					if (!ns)
					{
						ptr::shared_ptr<cache_rec> rec2 = NEW cache_rec(parser.ttl);
						netkit::ipap ip = netkit::ipap::build((const u8*)parser.cname.data(), 4, 0);
						cache_rec::add_ip(rec2->ips.lock_write()(), ip);

						DL(DLCH_DNS, "resolved %s with ip %s", parser.host.c_str(), ip.to_string(false).c_str());

						auto cw = cache.lock_write();
						cw().set(parser.host, rec2);
					}
				}

				continue;
			case dnspp::qtype_aaaa:

				if (ONLYIPV4)
					continue;

				if (parser.host == qi.host)
				{
					if (ASSERT(parser.cname.length() == 16))
					{
						rec_prepare();
						cache_rec::add_ip(rec->ips.lock_write()(), netkit::ipap::build((const u8*)parser.cname.data(), 16, 0));
						auto cw = cache.lock_write();
						cw().set(qi.host, rec);
					}
					continue;
				}

				if (parser.cname.length() == 16)
				{
					bool ns = false;
					for (signed_t ni = 0; ni < nns_count; ++ni)
					{
						newns& n = nns[ni];
						if (n.name->equals(parser.host))
						{
							cache_rec::add_ip(n.ips, netkit::ipap::build((const u8*)parser.cname.data(), 16, 53));
							ns = true;
							break;
						}
					}

					if (!ns)
					{
						ptr::shared_ptr<cache_rec> rec2 = NEW cache_rec(parser.ttl);
						cache_rec::add_ip(rec2->ips.lock_write()(), netkit::ipap::build((const u8*)parser.cname.data(), 16, 0));
						auto cw = cache.lock_write();
						cw().set(parser.host, rec2);
					}
				}

				continue;
			case dnspp::qtype_soa:
				empty_answer = true;
				continue; // just ignore soa
			default:
				return not_resolved(query_internals::r_notresolved);
			}

		}

		if (empty_answer && nns_count == 0 && !rec)
		{
			pr = dnspp::parse_empty;
		}

		if (pr == dnspp::parse_done)
		{
			const proxy* prx = qi.ns[qi.used_ips - 1]->prx; // keep proxy
			qi.on_success_request();

			if (nns_count > 0)
			{
				auto zns = zones.lock_write();
				for (signed_t ni = 0; ni < nns_count; ++ni)
				{
					newns& n = nns[ni];
					add_zone_ns(qi.ct, &zns(), n, str::view(n.zone), nullptr, prx);
				}
				zns.unlock();
			}

			if (rec)
			{
				if (rec->is_empty())
				{
					// cname
					ASSERT(qi.cnames_cnt > 1);

					if (qi.check_cname(qi.host))
					{
                        dns.prepare(qi.host);
                        rec = nullptr;
					}
					else
					{
						return not_resolved(query_internals::r_2manycnames);
					}
				}
				else
				{
					DL(DLCH_DNS, "resolved %s -> %s", qi.host.c_str(), rec->to_string(false).c_str());
					done_resolve(qi.cnames.data(), qi.cnames_cnt);
					return rec;
				}

			}

		}
		else if (pr == dnspp::parse_name_not_found || pr == dnspp::parse_empty)
		{
			if (!qi.last_ns)
				return not_resolved(query_internals::r_notresolved);

			if (!another_ip)
			{
				if (last_query_qtype == dnspp::qtype_a && glb.cfg.ipstack != conf::gip_only4)
				{
					last_query_qtype = dnspp::qtype_aaaa;
					if (!dns.build_query(last_query_qtype, parser.pg))
						return not_resolved(query_internals::r_request2big);
					another_ip = true;
					continue;
				}
				if (last_query_qtype == dnspp::qtype_aaaa && glb.cfg.ipstack != conf::gip_only6)
				{
					last_query_qtype = dnspp::qtype_a;
					if (!dns.build_query(last_query_qtype, parser.pg))
						return not_resolved(query_internals::r_request2big);
					another_ip = true;
					continue;
				}
			}
		}
		else
		{
			return not_resolved(query_internals::r_notresolved);
		}

		// prepare next try

		if (qi.used_ips == dnspp::maximum_fails)
		{
			return not_resolved(query_internals::r_notresolved);
		}

		if (find_ns(qi, 0))
			return shnr(qi);

		if (!qi.last_ns)
			return not_resolved(query_internals::r_notresolved);

		if (!dns.build_query(last_query_qtype, parser.pg))
			return not_resolved(query_internals::r_request2big);

	}

	UNREACHABLE();

}

netkit::io_result dns_resolver::query_internals::query(netkit::pgen& pg /* in/out*/)
{
	udp_transport* transport = transport_override;
	if (transport == nullptr)
		transport = this;

	netkit::udp_pipe* sender = transport;

	nameserver *n2s = ns[used_ips-1].get();
	if (n2s->prx)
	{
		sender = nullptr;
		for (proxy_pipe_data& pd : transport->ppipes)
		{
			if (pd.prx == n2s->prx)
			{
				sender = pd.pip.get();
				break;
			}
		}
		if (!sender)
		{
			proxy_pipe_data &pd = transport->ppipes.emplace_back(n2s->prx);
			pd.pip = n2s->prx->prepare(transport);
			sender = pd.pip.get();
		}
		if (!sender)
			return netkit::ior_general_fail;
	}


	netkit::io_result r = sender->send(n2s->ip, pg);
	if (r == netkit::ior_ok)
	{
		netkit::ipap from;
		return sender->recv(from, pg, dnspp::max_buf_size);
	}
	return r;
}

netkit::io_result dns_resolver::udp_transport::send(const netkit::endpoint& toaddr, const netkit::pgen& pg)
{
	return udp_send(*this, toaddr, pg);
}

netkit::io_result dns_resolver::udp_transport::recv(netkit::ipap& from, netkit::pgen& pg, signed_t max_bufer_size)
{
	return udp_recv(*this, from, pg, max_bufer_size);
}

void dns_resolver::load_serves(engine* e, const asts* s)
{
	auto nsl = servers.lock_write();
	auto zo = zones.lock_write();

	for (auto it = s->begin(); it; ++it)
	{
		if (it.is_comment())
			continue;
		str::astr nsn = it.name();
		str::astr options = it->as_string();
		size_t sl = options.find('/');
		if (sl == options.npos)
			sl = options.length();

		str::astr_view ips( options.c_str(), sl );
		cache_rec::ipsar ipar;
		TFORa(t, ips, ' ')
		{
			netkit::ipap ip = netkit::ipap::parse(*t);
			if (ip.is_wildcard())
			{
				LOG_W("dns ip [%s] addr skipped for name server {%s}", str::astr(*t).c_str(), nsn.c_str());
				continue;
			}
			if (ip.v4 && ONLYIPV6)
				continue;
			if (!ip.v4 && ONLYIPV4)
				continue;

			if (ip.port == 0)
				ip.port = 53;

			ipar.push_back(ip);
		}

		if (ipar.size() == 0)
		{
			LOG_W("nameserver {%s} has no address; skipped");
			continue;
		}


		newns nns;
		nns.name = str::shared_str::build(nsn);
		std::vector<str::astr_view> z4ns;
		const proxy* p = nullptr;
		if (sl < options.length())
		{
			bool skip = false;
			str::astr_view o(options.c_str() + sl + 1, options.length() - sl - 1);
			TFORa(tkn, o, '/')
			{
				if (tkn->starts_with(ASTR("zone:")))
				{
					z4ns.emplace_back(tkn->substr(5));
				} else if (tkn->starts_with(ASTR("proxy:")))
				{
					p = e->find_proxy(tkn->substr(6));
					if (!p)
					{
						LOG_W("proxy [%s] not found for name server [%s]", str::astr(tkn->substr(6)).c_str(), nns.name->to_string().c_str());
					}
					if (!p->support(netkit::ST_UDP))
					{
						LOG_W("proxy [%s] for name server [%s] does not support udp protocol; name server skipped", str::astr(tkn->substr(6)).c_str(), nns.name->to_string().c_str());
						skip = true;
						break;
					}
				}

			}
			if (skip)
				continue;
		}
		if (!z4ns.empty())
		{
			nns.ips = ipar;
			for (auto z : z4ns)
			{
				nns.zone = z;
				add_zone_ns(0, &zo(), nns, z, nullptr, p);
			}
		} else
		{
			for (const netkit::ipap& ip : ipar)
			{
				nameserver* ns = NEW nameserver(nns.name, ip);
				ns->prx = p;
				nsl().emplace_back(ns);
			}
		}
		size_t dot = nsn.find('.');
		if (dot == nsn.npos || dot == 0 || dot == nsn.size() - 1)
		{
			// just name
		}
		else
		{
			// domain name
			ptr::shared_ptr<cache_rec> rec(NEW cache_rec(std::move(ipar)));
			auto cw = cache.lock_write();
			cw().set(nsn, rec);
		}

	}

	zo.unlock();
}

