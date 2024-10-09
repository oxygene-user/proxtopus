#pragma once

#define MAXIMUM_SLOTS 30 // only 30 due each slot - two sockets, but maximum sockets per thread are 64

class listener;

#ifdef LOG_TRAFFIC
class traffic_logger
{
	signed_t id;
	HANDLE f21 = nullptr;
	HANDLE f12 = nullptr;
	str::astr fn;

	traffic_logger(traffic_logger&) = delete;
	traffic_logger& operator=(traffic_logger&) = delete;
	void prepare();
public:
	traffic_logger();
	~traffic_logger();
	traffic_logger& operator=(traffic_logger&&);
	void clear();
	void log12(u8* data, signed_t sz);
	void log21(u8* data, signed_t sz);
};
#endif

class handler
{
protected:

	struct bridged
	{
		netkit::pipe_ptr pipe1;
		netkit::pipe_ptr pipe2;
		size_t mask1 = 0;
		size_t mask2 = 0;

#ifdef LOG_TRAFFIC
		traffic_logger loger;
#endif

		void clear()
		{
			pipe1 = nullptr;
			pipe2 = nullptr;
			mask1 = 0;
			mask2 = 0;
#ifdef LOG_TRAFFIC
			loger.clear();
#endif
		}

		bool is_empty() const
		{
			return pipe1 == nullptr || pipe2 == nullptr;
		}

		bool prepare_wait(netkit::pipe_waiter& w)
		{
			mask1 = w.reg(pipe1); if (mask1 == 0) return false;
			mask2 = w.reg(pipe2); if (mask2 == 0)
			{
				w.unreg_last();
				return false;
			}
			return true;
		}

		enum process_result
		{
			SLOT_DEAD,
			SLOT_PROCESSES,
			SLOT_SKIPPED,
		};

		process_result process(u8* data, netkit::pipe_waiter::mask& masks); // returns: -1 - dead slot, 0 - slot not processed, 1 - slot processed

	};

	class tcp_processing_thread
	{
		//volatile spinlock::long3264 sync = 0;
		spinlock::syncvar<signed_t> numslots;
		netkit::pipe_waiter waiter;
		std::array<bridged, MAXIMUM_SLOTS> slots;
		std::unique_ptr<tcp_processing_thread> next;

		void moveslot(signed_t to, signed_t from)
		{
			ASSERT(to <= from);
			if (to < from)
			{
				slots[to] = std::move(slots[from]);
			}
			slots[from].pipe1 = nullptr;
			slots[from].pipe2 = nullptr;
#ifdef LOG_TRAFFIC
			slots[from].loger.clear();
#endif
		}

	public:
		void signal()
		{
			waiter.signal();
		}
		bool transplant(signed_t slot, tcp_processing_thread* to);
		tcp_processing_thread* get_next()
		{
			return next.get();
		}
		tcp_processing_thread* get_next_and_forget()
		{
			tcp_processing_thread* n = next.get();
			next.release();
			return n;
		}
		std::unique_ptr<tcp_processing_thread>* get_next_ptr()
		{
			return &next;
		}
		void close();
		signed_t try_add_bridge(netkit::pipe* pipe1, netkit::pipe* pipe2)
		{
			auto ns = numslots.lock_read();
			if (ns() < 0)
				return -1;
			if (ns() < MAXIMUM_SLOTS)
			{
				ns.unlock();
				auto nsw = numslots.lock_write();

				// check again
				if (nsw() < 0)
					return -1;
				if (nsw() >= MAXIMUM_SLOTS)
					return 0;

				ASSERT(slots[nsw()].pipe1 == nullptr);
				ASSERT(slots[nsw()].pipe2 == nullptr);

				slots[nsw()].pipe1 = pipe1;
				slots[nsw()].pipe2 = pipe2;
				slots[nsw()].mask1 = 0;
				slots[nsw()].mask2 = 0;
				++nsw();
				return 1;
			}
			return 0;
		}
		/*
		signed_t check()
		{
			return numslots.lock_read()() < 0 ? -1 : 0;
		}
		*/
		signed_t tick(u8 *data); // returns -1 to stop, 0..numslots - inactive slot index (4 forward), >MAXIMUM_SLOTS - do nothing
	};

	struct send_data
	{
        signed_t datasz;
		netkit::ipap tgt;

		static constexpr signed_t shift()
		{
			return math::maxv(32, sizeof(send_data));
		}

		u8* data()
		{
			return ((u8 *)this) + shift();
		}
        const u8* data() const
        {
			return ((const u8*)this) + shift();
        }

		u16 pre() const
		{
			return tools::as_word(shift());
		}
	};

	struct mfrees
	{
		void operator()(send_data* p)
		{
			free(p);
		}
	};

	using sdptr = std::unique_ptr<send_data, mfrees>;

	class udp_processing_thread : public netkit::udp_pipe
	{
		netkit::thread_storage ts; // for udp send
		netkit::ipap from;
		signed_t cutoff_time = 0;
		signed_t timeout = 5000;

		spinlock::syncvar<tools::fifo<sdptr>> sendb;

		std::unique_ptr<udp_processing_thread> next;
	public:
		void close();

		udp_processing_thread(signed_t timeout, const netkit::ipap &from /*, bool v4*/):timeout(timeout), from(from)
		{
			//udp_prepare(ts, v4);
		}

		void add2send(std::span<const u8> data, const netkit::ipap& tgt);

		/*virtual*/ netkit::io_result send(const netkit::ipap& toaddr, const netkit::pgen& pg) override;
		/*virtual*/ netkit::io_result recv(netkit::pgen& pg, signed_t max_bufer_size) override;

		bool has_from(const netkit::ipap& fa) const
		{
			return from.copmpare(fa);
		}

		bool is_timeout( signed_t curtime ) const
		{
			return cutoff_time != 0 && curtime >= cutoff_time;
		}

		void udp_bridge(SOCKET initiator);

		udp_processing_thread* get_next()
		{
			return next.get();
		}
		udp_processing_thread* get_next_and_forget()
		{
			udp_processing_thread* n = next.get();
			next.release();
			return n;
		}
		std::unique_ptr<udp_processing_thread>* get_next_ptr()
		{
			return &next;
		}

	};

	spinlock::syncvar<std::unique_ptr<tcp_processing_thread>> tcp_pth; // list of tcp threads
	spinlock::syncvar<std::unique_ptr<udp_processing_thread>> udp_pth; // list of udp threads

	listener* owner;
	std::vector<const proxy*> proxychain;

	volatile bool need_stop = false;

	void bridge(netkit::pipe_ptr &&pipe1, netkit::pipe_ptr &&pipe2); // either does job in current thread or forwards job to another thread with same endpoint
	void bridge(tcp_processing_thread *npt);

	void release_udp(udp_processing_thread *udp_wt);
	void release_tcp(tcp_processing_thread* udp_wt);

public:
	handler(loader& ldr, listener* owner, const asts& bb);
	virtual ~handler() { stop(); }

	void stop();
	netkit::pipe_ptr connect(const netkit::endpoint& addr, bool direct); // just connect to remote host using current handler's proxy settings

	virtual str::astr desc() const = 0;
	virtual bool compatible(netkit::socket_type /*st*/) const
	{
		return false;
	}

	virtual void on_pipe(netkit::pipe* pipe)  // called from listener thread, execute as fast as possible
	{
		// so, this func is owner of pipe now
		// delete it
		// (override this to handle pipe)
		delete pipe; 
	}

	virtual void on_udp(netkit::socket &, const netkit::udp_packet& )
	{
		// do nothing by default
	}


	static handler* build(loader& ldr, listener *owner, const asts& bb, netkit::socket_type st);
};


class handler_direct : public handler // just port mapper
{
	str::astr to_addr; // in format like: tcp://domain_or_ip:port

	spinlock::syncvar<netkit::ipap> tgt_ip;

	void tcp_worker(netkit::pipe* pipe); // sends all from pipe to out connection
	void udp_worker(netkit::socket* lstnr, udp_processing_thread* udp_wt);
	signed_t udp_timeout_ms = 5000;

public:
	handler_direct( loader &ldr, listener* owner, const asts& bb, netkit::socket_type st );
	virtual ~handler_direct() { stop(); }

	/*virtual*/ str::astr desc() const { return str::astr(ASTR("direct")); }
	/*virtual*/ bool compatible(netkit::socket_type /*st*/) const
	{
		return true; // compatible with both tcp and udp
	}

	/*virtual*/ void on_pipe(netkit::pipe* pipe) override;
	/*virtual*/ void on_udp(netkit::socket& lstnr, const netkit::udp_packet& p) override;
};

class handler_socks : public handler // socks4 and socks5
{
	enum rslt
	{
		EC_GRANTED,
		EC_FAILED,
		EC_REMOTE_HOST_UNRCH,
	};

	str::astr userid; // for socks4
	str::astr login, pass; // for socks5

	bool socks5_allow_anon = false;
	
	bool allow_4 = true;
	bool allow_5 = true;

	void handshake4(netkit::pipe* pipe);
	void handshake5(netkit::pipe* pipe);

	void handshake(netkit::pipe* pipe);

	using sendanswer = std::function< void(netkit::pipe* pipe, rslt ecode) >;

	void worker(netkit::pipe* pipe, const netkit::endpoint& inf, sendanswer answ);

public:
	handler_socks(loader& ldr, listener* owner, const asts& bb, const str::astr_view &st);
	virtual ~handler_socks() { stop(); }

	/*virtual*/ str::astr desc() const { return str::astr(ASTR("socks")); }
	/*virtual*/ bool compatible(netkit::socket_type st) const
	{
		return st == netkit::ST_TCP;
	}

	/*virtual*/ void on_pipe(netkit::pipe* pipe) override;
};

#include "handler_ss.h"
