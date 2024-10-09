#pragma once

#ifdef _WIN32
#include <winsock2.h>
#include <Mmsystem.h>
#endif

#define LOOP_PERIOD 500000 // 0.5 sec

#ifdef _NIX
inline void closesocket(int s) { ::close(s); };
#define MAXIMUM_WAITABLES 64
#define SOCKET int
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#endif

struct thread_storage;

namespace netkit
{
	template <bool native_little> struct cvt {};
	template<> struct cvt<true> {
		static inline u16 to_ne(u16 v_nitive) // convert to network-endian
		{
			return ((v_nitive & 0xff) << 8) | ((v_nitive >> 8) & 0xff);
		}
		static inline u16 to_he(u16 v_network) // convert to host-endian
		{
			return ((v_network & 0xff) << 8) | ((v_network >> 8) & 0xff);
		}
	};
	template<> struct cvt<false> {
		static inline u16 to_ne(u16 v_nitive) // convert to network-endian
		{
			return v_nitive;
		}
		static inline u16 to_he(u16 v_network) // convert to host-endian
		{
			return v_network;
		}
	};

	inline u16 to_ne16(signed_t v_nitive)
	{
		return cvt<Endian::little>::to_ne((u16)(v_nitive & 0xffff));
	}

	inline u16 to_ne(u16 v_nitive)
	{
		return cvt<Endian::little>::to_ne(v_nitive);
	}
	inline u16 to_he(u16 v_network)
	{
		return cvt<Endian::little>::to_he(v_network);
	}

	enum socket_type
	{
		ST_UNDEFINED,
		ST_TCP,
		ST_UDP,
	};

	struct udp_packet;
	struct ipap // ip address and port
	{
		static ipap parse6(const str::astr_view& s); // assume s is ipv6 address
		static ipap parse(const str::astr_view& s);
		static void build(ipap* r, const u8* packet, signed_t plen, u16 port = 0)
		{
			bool readport = false;
			if (port == 0 && (plen == 6 || plen == 18))
			{
				plen -= 2;
				readport = true;
			}

			if (plen == 4)
			{
				r->ipv4 = *(in_addr*)packet;
			}
			else if (plen == 16) {
				memcpy(&r->ipv6, packet, 16);
				r->v4 = false;
			}
			if (readport)
			{
				r->port = ((u16)packet[plen] << 8) | packet[plen + 1];
			}
			else
				r->port = port;
		}
		static ipap build(const u8* packet, signed_t plen, u16 port = 0)
		{
			ipap r;
			build(&r, packet, plen, port);
			return r;
		}

		static ipap localhost(bool v4)
		{
		    return ipap(v4).init_localhost();
		}

		union
		{
			in_addr ipv4;
			in6_addr ipv6;
		};

		u16 port = 0; // in native order (will be converted to network order directly while filling sockaddr_in or sockaddr_in6 structures)
		bool v4 = true;

		void clear()
		{
			v4 = glb.cfg.ipstack == conf::gip_only4 || glb.cfg.ipstack == conf::gip_prior4;
			if (v4) ipv4.s_addr = 0; else memset(&ipv6, 0, sizeof(ipv6));
		}

		ipap &init_localhost()
		{
            if (u8* dst = octets())
            {
                *(dst+0) = 127;
                *(dst+1) = 0;
                *(dst+2) = 0;
                *(dst+3) = 1;
            } else {
                u16 * w = reinterpret_cast<u16*>(&ipv6);
                w[0] = 0;
                w[1] = 0;
                w[2] = 0;
                w[3] = 0;
                w[4] = 0;
                w[5] = 0;
                w[6] = 0;
                w[7] = to_ne(1);
            }
		    return *this;
		}

		bool is_wildcard() const
		{
		    if (v4) return ipv4.s_addr == 0;
		    const u64 * d = reinterpret_cast<const u64*>(&ipv6);
		    return d[0] == 0 && d[1] == 0;

		}

		ipap()
		{
			clear();
		}
		explicit ipap(bool v4):v4(v4)
		{
		}

		/*
		explicit ipap(const sockaddr_in &a) {
			ipv4.s_addr = a.sin_addr.s_addr;
			port = netkit::to_he(a.sin_port);
		}
		explicit ipap(const sockaddr_in6& a):v4(false) {
			memcpy(&ipv6, &a.sin6_addr, sizeof(a.sin6_addr));
			port = netkit::to_he(a.sin6_port);
		};
		*/
		explicit ipap(const void *aaaa, signed_t aaaa_size) :v4(aaaa_size == sizeof(sockaddr_in)) {
			if (v4)
			{
				const sockaddr_in* a = (const sockaddr_in*)aaaa;
				ipv4.s_addr = a->sin_addr.s_addr;
				port = netkit::to_he(a->sin_port);
			}
			else
			{
				const sockaddr_in6* a = (const sockaddr_in6*)aaaa;
				memcpy(&ipv6, &a->sin6_addr, sizeof(a->sin6_addr));
				port = netkit::to_he(a->sin6_port);
			}
		};

		ipap& operator=(const ipap& ip)
		{
			if (ip.v4)
			{
				ipv4.s_addr = ip.ipv4.s_addr;
				v4 = true;
			}
			else {
				memcpy(&ipv6, &ip.ipv6, sizeof(ipv6));
				v4 = false;
			}
#ifdef _DEBUG
			if (port == 53 && ip.port == 0)
				__debugbreak();
#endif
			port = ip.port;
			return *this;
		}

		void set(const ipap& ip, bool useport)
		{
			v4 = ip.v4;
			if (v4)
				ipv4.s_addr = ip.ipv4.s_addr;
			else
				memcpy(&ipv6, &ip.ipv6, sizeof(ipv6));
			if (useport)
				port = ip.port;
		}
		void set(const sockaddr_in* ip4, bool useport)
		{
			v4 = true;
			ipv4.s_addr = ip4->sin_addr.s_addr;
			if (useport)
				port = netkit::to_he(ip4->sin_port);
		}
		void set(const sockaddr_in6* ip6, bool useport)
		{
			v4 = false;
			memcpy(&ipv6, &ip6->sin6_addr, sizeof(ip6->sin6_addr));
			if (useport)
				port = netkit::to_he(ip6->sin6_port);
		}

		void operator=(const addrinfo *addr)
		{
			clear();

			for (; addr != nullptr; addr = addr->ai_next) {

				if (addr->ai_family == AF_INET) { // IPv4
					set((sockaddr_in*)addr->ai_addr, true);
					break;
				}
				else if (addr->ai_family == AF_INET6) { // IPv6
					set((sockaddr_in6*)addr->ai_addr, true);
					break;
				}
			}
		}

		ipap& set_port(signed_t p)
		{
			this->port = tools::as_word(p);
			return *this;
		}

		const u8* octets() const
		{
			return v4 ? reinterpret_cast<const u8*>( &ipv4 ) : nullptr;
		}
		u8* octets()
		{
			return v4 ? reinterpret_cast<u8*>(&ipv4) : nullptr;
		}

		u16* words()
		{
			return !v4 ? reinterpret_cast<u16*>(&ipv6) : nullptr;
		}
		const u16* words() const
		{
			return !v4 ? reinterpret_cast<const u16*>(&ipv6) : nullptr;
		}

		str::astr to_string(bool with_port) const
		{
			if (const u8 *octs = octets())
			{
				str::astr s = std::to_string(octs[0]);
				s.push_back('.'); s.append(std::to_string(octs[1]));
				s.push_back('.'); s.append(std::to_string(octs[2]));
				s.push_back('.'); s.append(std::to_string(octs[3]));
				if (with_port)
				{
					s.push_back(':');
					s.append(std::to_string(port));
				}
				return s;
			}
			if (const u16* ww = words())
			{
				str::astr s; if (with_port) s.push_back('[');

				bool col = false, clp = false;
				bool needz = false;
				for (signed_t i = 0; i < 8; ++i)
				{
					u16 w = ww[i];
					if (w == 0 && !needz)
					{
						if (!col)
						{
							if (clp)
								s.push_back(':');
							else
								s.append(ASTR("::"));
						}
						col = true;
					}
					else
					{
						if (col)
							needz = true;
						str::append_hex(s, netkit::to_he(w));
						if (i < 7)
						{
							clp = true;
							s.push_back(':');
						}
					}


				}

				if (with_port)
				{
					s.append(ASTR("]:"));
					s.append(std::to_string(port));
				}
				return s;
			}

			UNREACHABLE();
		}

		bool copmpare(const ipap& a) const
		{
			if (v4 && a.v4)
				return port == a.port && ipv4.s_addr == a.ipv4.s_addr;
			if (!v4 && !a.v4)
				return port == a.port && memcmp(&ipv6, &a.ipv6, sizeof(ipv6)) == 0;
			return false;
		}
		bool copmpare_a(const ipap& a) const
		{
			if (v4 && a.v4)
				return ipv4.s_addr == a.ipv4.s_addr;
			if (!v4 && !a.v4)
				return memcmp(&ipv6, &a.ipv6, sizeof(ipv6)) == 0;
			return false;
		}

		bool operator==(const ipap& a) = delete;

		operator u32() const {
			return v4 ? ipv4.s_addr : 0;
		}

		operator bool() const
		{
			return !is_wildcard();
		}

		/*
		operator u128() const {
			return !v4 ? *(u128 *)&ipv6 : 0;
		}
		*/

		bool bind(SOCKET s) const;
		bool connect(SOCKET s) const;
		bool sendto(SOCKET s, const std::span<const u8> &p) const;
	};

	enum endpoint_state
	{
		EPS_EMPTY,
		EPS_DOMAIN,
		EPS_RESLOVED,
	};

	enum wrslt
	{
		WR_TIMEOUT,
		WR_READY4READ,
		WR_CLOSED,
	};

#ifdef _WIN32
#define MAXIMUM_WAITABLES (MAXIMUM_WAIT_OBJECTS - 2)
#endif

#define READY_SYSTEM 1	// ready by WSAEnumNetworkEvents/select
#define READY_PIPE 2	// ready by parent pipe

	struct waitable_data
	{
#ifdef _WIN32
		WSAEVENT wsaevent = nullptr;
#endif
		SOCKET s = INVALID_SOCKET;
		u8 ready = 0;
		u8 bufferfull = 0; // _NIX
		u8 reserved1, reserved2;
		void operator=(SOCKET s_) { s = s_; }
	};
	NIXONLY( static_assert(sizeof(waitable_data) == 8); )
	using WAITABLE = waitable_data*;
	inline bool is_ready(WAITABLE w) { return w->ready != 0; }
	inline void make_ready(WAITABLE w, signed_t mask) { w->ready |= mask; }
	inline void clear_ready(WAITABLE w, signed_t mask) { w->ready &= ~mask; }
#define NULL_WAITABLE ((netkit::WAITABLE)nullptr)

	wrslt wait(WAITABLE s, long microsec);

	struct pipe;
	class pipe_waiter
	{
		using ppipe = pipe*;
		ppipe pipes[MAXIMUM_WAITABLES];
#ifdef _WIN32
		SOCKET soks[MAXIMUM_WAITABLES + 2];
		WSAEVENT www[MAXIMUM_WAITABLES + 2];
		WSAEVENT sig = nullptr;
#endif
#ifdef _NIX
        pollfd polls[MAXIMUM_WAITABLES + 2];
        int evt[2] = {INVALID_SOCKET, INVALID_SOCKET}; // socketpair
#endif // _NIX
		signed_t numw = 0;
		u64 readymask = 0;

		static_assert(MAXIMUM_WAITABLES <= 64);

	public:

		class mask
		{
			u64 readm = 0;
			u64 closem = 0;
			u64 writem = 0;

		public:
			mask(u64 readmask = 0):readm(readmask)
			{
			}

			bool have_read(u64 m)
			{
				if ((readm & m) != 0)
				{
					readm &= ~m;
					return true;
				}
				return false;
			}
			bool have_closed(u64 m)
			{
				if ((closem & m) != 0)
				{
					closem &= ~m;
					return true;
				}
				return false;
			}
			bool have_write(u64 m)
			{
				if ((writem & m) != 0)
				{
					writem &= ~m;
					return true;
				}
				return false;
			}

			void add_read(u64 m) { readm |= m; }
			void add_close(u64 m) { closem |= m; }
			void add_write(u64 m) { writem |= m; }

			void remove_read(u64 m) { readm &= ~m; }
			void remove_close(u64 m) { closem &= ~m; }
			void remove_write(u64 m) { writem &= ~m; }

			bool is_empty() const { return readm == 0 && closem == 0 && writem == 0; }
		};

#ifdef _NIX
        mask checkall();
#endif // _NIX


		~pipe_waiter()
		{
#ifdef _WIN32
			if (sig)
				WSACloseEvent(sig);
#endif
#ifdef _NIX
            if (evt[0] >= 0)
            {
                ::close(evt[0]);
                ::close(evt[1]);
            }

#endif // _NIX
		}

		u64 reg(pipe* p);
		void unreg_last();

		mask wait(long microsec); // after wait return, waiter is in empty state
		void signal();
	};

	class endpoint
	{
		str::astr domain_;
		mutable ipap ip;
		mutable endpoint_state state_ = EPS_EMPTY;
		mutable socket_type sockt = ST_UNDEFINED;

		void check_domain_or_ip();

	public:

		endpoint() {}
		explicit endpoint(const str::astr& addr);
		endpoint(const ipap &ip):ip(ip), state_(EPS_RESLOVED) {}

		bool operator==(const endpoint& ep)
		{
			switch (state_)
			{
			case EPS_DOMAIN:

				if (ep.state_ == EPS_DOMAIN)
					return domain_ == ep.domain_;

				if (ep.state_ == EPS_RESLOVED)
					return ip.copmpare(ep.ip);

				return false;
			case netkit::EPS_RESLOVED:
				return ip.copmpare(ep.ip);
			}
			return false;
		}

		void preparse(const str::astr& addr);

		void read(u8* packet, signed_t plen)
		{
			ipap::build(&ip, packet, plen);
			state_ = EPS_RESLOVED;
		}

		void set_ipap(const ipap &ip_)
		{
			this->ip = ip_;
			state_ = EPS_RESLOVED;
		}

		void set_port(signed_t p)
		{
			this->ip.port = (u16)p;
		}

		void set_domain(const str::astr& dom)
		{
			this->domain_ = dom;
			state_ = EPS_DOMAIN;
		}
		void set_domain(const str::astr_view& dom)
		{
			this->domain_ = dom;
			state_ = EPS_DOMAIN;
		}

		ipap get_ip(size_t options) const;

		signed_t port() const
		{
			return ip.port;
		}
		endpoint_state state() const
		{
			return state_;
		}
		socket_type socket_type() const
		{
			return sockt;
		}
		str::astr domain() const
		{
			return domain_;
		}
		str::astr desc() const
		{
			str::astr d(domain_);
			if (!d.empty())
			{
				d.push_back(':'); d.append(std::to_string(ip.port));
			}
			switch (state_)
			{
			case netkit::EPS_DOMAIN:
				break;
			case netkit::EPS_RESLOVED:
				if (d.empty())
				{
					d = ip.to_string(true);
				}
				else
				{
					str::astr ipa = ip.to_string(false);
					if (d.find(ipa) == d.npos)
					{
						d.append(ASTR(" ("));
						d.append(ipa);
						d.push_back(')');
					}
				}
				break;
			default:
				if (!d.empty()) d.push_back(' ');
				d.append(ASTR("(unresolved)"));
				break;
			}
			return d;
		}
	};

	struct udp_packet
	{
		u8	packet[65536];
		ipap from;
		u16 sz = 0;
		udp_packet(bool v4)
		{
			from.v4 = v4;
		}

		std::span<const u8> to_span() const
		{
			return std::span<const u8>(packet, sz);
		}
	};

	struct tcp_pipe;

	struct socket
	{
		SOCKET s = INVALID_SOCKET;

		bool ready() const { return s != INVALID_SOCKET; }
		virtual ~socket() { close(false); }

		void close(bool flush_before_close);

		bool init(signed_t timeout, bool v4);
		bool listen_udp(const str::astr& name, const ipap& bind2);
		bool recv(udp_packet& p);
		bool send(const std::span<const u8>& p, const ipap& tgt_ip);
	};


	struct waitable_socket
	{
		waitable_data _socket;
		SOCKET sock() const { return _socket.s; }
		WAITABLE get_waitable()
		{
#ifdef _WIN32
			if (_socket.wsaevent == nullptr)
			{
				_socket.wsaevent = WSACreateEvent();
				WSAEventSelect(_socket.s, _socket.wsaevent, FD_READ|FD_CLOSE);
			}
#endif
			return &_socket;
		}

		void close(bool flush_before_close);
		bool ready() const { return sock() != INVALID_SOCKET; }
		virtual ~waitable_socket() { close(false); }

		bool listen(const str::astr& name, const ipap& bind2);
		tcp_pipe* tcp_accept(const str::astr& name);

	};

	struct pipe : public ptr::sync_shared_object
	{
		enum sendrslt
		{
			SEND_OK,
			SEND_FAIL,
			SEND_BUFFERFULL,
		};

		pipe() {}
		virtual ~pipe() {}

		pipe(const tcp_pipe&) = delete;
		pipe(tcp_pipe&&) = delete;

		virtual sendrslt send(const u8* data, signed_t datasize) = 0;
		virtual signed_t recv(u8* data, signed_t maxdatasz) = 0;
		virtual WAITABLE get_waitable() = 0;
		virtual void close(bool flush_before_close) = 0;
		virtual bool alive() = 0;
	};

	using pipe_ptr = ptr::shared_ptr<pipe>;

	struct tcp_pipe : public pipe, public waitable_socket
	{
		ipap addr;
		signed_t creationtime = 0;

		tools::circular_buffer<16384*3> rcvbuf;
		tools::chunk_buffer<16384> outbuf;

		tcp_pipe() { creationtime = chrono::ms(); }
		tcp_pipe(SOCKET s, const ipap& addr) :addr(addr) { _socket = s; creationtime = chrono::ms(); }
		tcp_pipe(const tcp_pipe&) = delete;
		tcp_pipe(tcp_pipe&&) = delete;

		~tcp_pipe()
		{
		}

		/*virtual*/ void close(bool flush_before_close) override
		{
			rcvbuf.clear();
			waitable_socket::close(flush_before_close);
		}

		bool timeout() const
		{
			return (chrono::ms() - creationtime) > 10000; // 10 sec
		}

		void set_address(const ipap &ipp)
		{
			addr = ipp;
		}
		void set_address(const endpoint & ainf)
		{
			set_address( ainf.get_ip(glb.cfg.ipstack | conf::gip_any) );
		}

		bool connect();

		tcp_pipe& operator=(tcp_pipe&& p)
		{
			if (connected())
				close(false);

			_socket = p._socket; p._socket = INVALID_SOCKET;
			addr = p.addr;
			rcvbuf = std::move(p.rcvbuf);
			return *this;
		}

		bool connected() const { return ready(); }

		/*virtual*/ bool alive() override;


		/*virtual*/ sendrslt send(const u8* data, signed_t datasize) override;
		/*virtual*/ signed_t recv(u8* data, signed_t maxdatasz) override;

		enum read_result : u8
		{
			OK,
			NOT_YET_READY,
			DEAD
		};

		template<signed_t N> using ret_t = std::tuple<vbv<N>, read_result>;

		/*
		template<signed_t N> ret_t<N> read(signed_t shift)
		{
			rcv_all();
			if (rcvbuf.datasize() >= N + shift)
			{
				return { vbv<N>(rcvbuf + shift), OK };
			}
			return { vbv<N>(), connected() ? NOT_YET_READY : DEAD };
		}
		*/


		bool rcv_all(); // receive all, but stops when buffer size reaches 64k
		/*virtual*/ WAITABLE get_waitable() override;

		/*
		void cpdone(signed_t psz) // current packet done
		{
			if (rcvbuf_sz == psz)
				rcvbuf_sz = 0;
			else if (rcvbuf_sz > psz)
			{
				rcvbuf_sz -= psz;
				memcpy(rcvbuf, rcvbuf + psz, rcvbuf_sz);
			}
		}
		*/
	};

	static_assert(sizeof(tcp_pipe) <= 65536);


	bool dnsresolve(const str::astr& host, ipap& addr, bool log_it);



	class pgen
	{
		u8* data;

		void use_pre(signed_t res) // res can be positive and negative
		{
			ASSERT(res > 0 ? pre >= res : (pre - res) <= sz);
			pre = tools::as_word(pre - res);
			data = data - res;
			sz = tools::as_word(sz + res);
		}

	public:
		u16 ptr = 0;
		u16 sz, pre = 0;
		pgen(u8* data, signed_t sz, signed_t pre = 0) :data(data), sz(tools::as_word(sz)), pre(tools::as_word(pre)) {}
		explicit pgen(std::span<const u8> data) :data(const_cast<u8 *>(data.data())), sz(tools::as_word(data.size())) {} // yeah, const hack
		~pgen() {
		}

		void set_pre(u16 reqpre)
		{
			if (reqpre == pre)
				return;
			signed_t delta = (signed_t)pre - (signed_t)reqpre;
			use_pre(delta);
		}

		void operator=(const udp_packet& p)
		{
			memcpy(data, p.packet, p.sz);
			sz = ptr = p.sz;
		}

		std::span<const u8> to_span() const
		{
			return std::span<const u8>(data, sz);
		}

		void start()
		{
			ptr = 0;
		}

		const u8* raw() const
		{
			return data + ptr;
		}
		u8* get_data()
		{
			return data;
		}

		str::astr_view str_view(signed_t ssz)
		{
			for (char* c = (char*)data + ptr, *e = (char*)data + ptr + ssz; c < e; ++c)
			{
				char ch = *c;
				if (ch >= 'A' && ch <= 'Z')
				{
					*c = ch + 32;
				}
			}

			return str::astr_view( (const char *)data + ptr, ssz);
		}

		bool skipn(signed_t n)
		{
			ptr += tools::as_word(n);
			return ptr <= sz;
		}

		bool enough(signed_t numb) const
		{
			return ptr + numb <= sz;
		}

		u16 read16()
		{
			ASSERT(enough(2));
			u16 rv = (((u16)data[ptr]) << 8) | data[ptr+1];
			ptr += 2;
			return rv;
		}
		u32 read32()
		{
			ASSERT(enough(4));
			u32 rv = (((u32)data[ptr]) << 24) | (((u32)data[ptr + 1]) << 16) | (((u32)data[ptr+2]) << 8) | (((u32)data[ptr+3]) << 0);
			ptr += 4;
			return rv;
		}

		template<typename T> const T* readstruct()
		{
			if (ptr + (signed_t)sizeof(T) > sz)
				return nullptr;
			T* t = (T *)(data + ptr);
			ptr += sizeof(T);
			return t;
		}
		template<typename T> T get()
		{
			if (ptr + (signed_t)sizeof(T) > sz)
				return (T)0;
			T* t = (T*)(data + ptr);
			ptr += sizeof(T);
			return *t;
		}

		template<typename S> S & pushstruct()
		{
			memset(data + ptr, 0, sizeof(S));
			S& s = *(S*)(data + ptr);
			ptr += sizeof(S);
			return s;
		}

		void pusha(const u8* a, signed_t asz)
		{
			memcpy(data + ptr, a, asz);
			ptr += tools::as_word(asz);
		}
		void pushz(signed_t zsz)
		{
			memset(data + ptr, 0, zsz);
			ptr += tools::as_word(zsz);
		}

		void push8(signed_t b)
		{
			data[ptr++] = (u8)b;
		}
		void push16(signed_t b) // push in big endiang order
		{
			data[ptr++] = (u8)((b >> 8) & 0xff); // high first
			data[ptr++] = (u8)((b) & 0xff); // low second
		}
		void pushs(const str::astr& s)
		{
			data[ptr++] = (u8)s.length();
			memcpy(data + ptr, s.c_str(), s.length());
			ptr += tools::as_word(s.length());
		}
		void push(const netkit::ipap &ip, bool push_port) // push ip
		{
			if (ip.v4)
			{
				memcpy(data + ptr, &ip.ipv4, 4);
				ptr += 4;
			}
			else {
				memcpy(data + ptr, &ip.ipv6, 16);
				ptr += 16;
			}
			if (push_port)
			{
				push16(ip.port);
			}
		}
	};

	struct thread_storage_data
	{
		virtual ~thread_storage_data() {}
	};

	struct thread_storage
	{
		std::unique_ptr<thread_storage_data> data;
	};

	enum io_result
	{
		ior_ok,
		ior_general_fail,
		ior_proxy_fail,
		ior_send_failed,
		ior_timeout,
	};

	class udp_pipe
	{
	public:
		virtual ~udp_pipe() {}

		virtual io_result send(const ipap &toaddr, const pgen& pg /* in */) = 0;
		virtual io_result recv(pgen& pg /* out */, signed_t max_bufer_size /*used as max size of answer*/) = 0;
	};

	void udp_prepare(thread_storage& ts, bool v4);
	io_result udp_send(thread_storage& ts, const ipap& toaddr, const pgen& pg /* in */);
	io_result udp_recv(thread_storage& ts, pgen& pg /* out */, signed_t max_bufer_size /*used as max size of answer*/);


}

