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


class apiobj
{
	friend class engine;
    signed_t id = 0;
public:
	signed_t get_id() const { return id; }
    virtual ~apiobj() {}
	virtual void api(json_saver& j) const
	{
		if (id != 0)
			j.field(ASTR("id"), id);
	}
};


class handler : public apiobj
{
	friend class listener;
protected:

	struct bridged
	{
		netkit::pipe_ptr pipe1;
		netkit::pipe_ptr pipe2;
		u64 mask1 = 0;
		u64 mask2 = 0;

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
		str::astr name;
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

        tcp_processing_thread()
        {
            spinlock::increment(glb.numtcp);
        }
        ~tcp_processing_thread()
        {
            spinlock::decrement(glb.numtcp);
        }

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
        netkit::endpoint tgt;
        signed_t datasz;

		static consteval signed_t plain_tail_start() // get size of plain tail of this structure
		{
			return netkit::endpoint::plain_tail_start(); /* + offsetof(send_data, tgt) */
		}

		u8* data()
		{
			return ((u8 *)(this+1));
		}
        const u8* data() const
        {
			return ((const u8*)(this+1));
        }

		static u16 pre()
		{
			return tools::as_word(sizeof(send_data) - plain_tail_start());
		}

		static send_data* build(std::span<const u8> data, const netkit::endpoint& tgt)
		{
			if (send_data* sd = (send_data*)malloc(sizeof(send_data) + data.size()))
            {
				new (sd) send_data(tgt, data.size());
                memcpy(sd->data(), data.data(), data.size());
				return sd;
			}
			return nullptr;
		}

	private:
        send_data(const netkit::endpoint &tgt, signed_t datasz):tgt(tgt), datasz(datasz) {} // do not allow direct creation

	};

	struct mfrees
	{
		void operator()(send_data* p)
		{
			p->~send_data();
			free(p);
		}
	};

	using sdptr = std::unique_ptr<send_data, mfrees>;

	class udp_processing_thread : public netkit::udp_pipe, public ptr::sync_shared_object
	{
		handler* h = nullptr;
		netkit::thread_storage ts; // for udp connection to 2nd peer
		netkit::thread_storage handler_state; // internal per-thread handler's state
		netkit::ipap hashkey;
		signed_t cutoff_time = 0;
		spinlock::syncvar<tools::fifo<sdptr>> sendb;
		netkit::udp_pipe *sendor = nullptr;

	public:

		udp_processing_thread(handler *h, netkit::thread_storage &&hs, const netkit::ipap & k):h(h), handler_state(std::move(hs)), hashkey(k)
		{
			spinlock::increment(glb.numudp);
			update_cutoff_time();
		}
        ~udp_processing_thread()
        {
            spinlock::decrement(glb.numudp);
        }

		const netkit::ipap& key() const
		{
			return hashkey;
		}

		netkit::thread_storage* geths()
		{
			return &handler_state;
		}

		void update_cutoff_time()
		{
			auto to = h->udp_timeout();
			cutoff_time = to == 0 ? 0 : chrono::ms() + to;
		}
		void close();

		void convey(netkit::pgen &p, const netkit::endpoint& tgt);

		/*virtual*/ netkit::io_result send(const netkit::endpoint& toaddr, const netkit::pgen& pg) override;
		/*virtual*/ netkit::io_result recv(netkit::ipap& from, netkit::pgen& pg, signed_t max_bufer_size) override;

		bool is_timeout( signed_t curtime ) const
		{
			return cutoff_time != 0 && curtime >= cutoff_time;
		}

		void udp_bridge(SOCKET initiator);

	};

	RWLOCK lock_tcp_list = 0;
	std::unique_ptr<tcp_processing_thread> tcps; // list of tcp threads
	std::unordered_map<netkit::ipap, ptr::shared_ptr<udp_processing_thread>> udp_pth; // only accept thread can modify this map
	spinlock::syncvar<std::vector<netkit::ipap>> finished; // keys of finished threads

	listener* owner;
	std::vector<const proxy*> proxychain;
	const proxy* udp_proxy = nullptr;

	volatile bool need_stop = false;

	void bridge(netkit::pipe_ptr &&pipe1, netkit::pipe_ptr &&pipe2); // either does job in current thread or forwards job to another thread with same endpoint
	void bridge(tcp_processing_thread *npt);

	void release_udps(); // must be called from listener thread
	void release_udp(udp_processing_thread *udp_wt);
	void release_tcp(tcp_processing_thread* udp_wt);
	void udp_worker(netkit::socket* lstnr, udp_processing_thread* udp_wt);

	/*
	*
	*   handle udp request: initiator -> handler -> remote
	*
	*   p (in/modif) - packet from initiator, can be modified
	*   ep (out) - address of remote
	*   pg (out) - packet to send to remote (refs to p.packet)
	*
	*/
	virtual bool handle_packet(netkit::thread_storage& /*ctx*/, netkit::udp_packet& /*p*/, netkit::endpoint& /*ep*/, netkit::pgen& /*pg*/)
	{
		return false;
	}

	/*
	*
	*   handle udp answer: initiator <- handler <- remote
	*
	*   ctx (in) - context of handler per thread (created in handle_packet)
	*   from (in) - packet source
	*   pg (in/out) - packet, received from remote; modified (or not modified) one will be send to initiator
	*
	*   return false to stop bridging of current udp stream
	*/
	virtual bool encode_packet(netkit::thread_storage& /*ctx*/, const netkit::ipap& /*from*/, netkit::pgen& /*pg*/)
    {
        return true;
    }

	virtual signed_t udp_timeout() const // ms
	{
		return 10000;
	}
	virtual void log_new_udp_thread(const netkit::ipap& /*from*/, const netkit::endpoint& /*to*/) {}


public:
	handler(loader& ldr, listener* owner, const asts& bb);
	handler() {}
	virtual ~handler() { stop(); }

	void stop();
	netkit::pipe_ptr connect(netkit::endpoint& addr, bool direct); // just connect to remote host using current handler's proxy settings

	using mbresult = std::function< void(bool connection_established) >;
	void make_bridge(const str::astr& epa, netkit::pipe* clientpipe, mbresult res);

	/*virtual*/ void api(json_saver&) const override;

	virtual str::astr desc() const = 0;
	virtual bool compatible(netkit::socket_type_e /*st*/) const
	{
		return false;
	}

	virtual void handle_pipe(netkit::pipe* pipe)  // will be called in new thread, so can work as long as need
	{
		// this func is owner of pipe now
		// delete it
		// (override this to handle pipe)
		delete pipe;
	}

    void udp_dispatch(netkit::socket&, netkit::udp_packet&);
    virtual void on_listen_port(signed_t /*port*/) {} // callback on listen port

	static handler* new_handler(loader& ldr, listener *owner, const asts& bb, netkit::socket_type_e st);
};


class handler_direct : public handler // just port mapper
{
	str::astr to_addr; // in format like: tcp://domain_or_ip:port
	netkit::endpoint ep; // only accessed from listener thread

	signed_t udp_timeout_ms = 10000;

protected:
	/*virtual*/ bool handle_packet(netkit::thread_storage& ctx, netkit::udp_packet& p, netkit::endpoint& epr, netkit::pgen& pg) override;
    /*virtual*/ signed_t udp_timeout() const override
    {
        return udp_timeout_ms;
    }
	/*virtual*/ void log_new_udp_thread(const netkit::ipap& from, const netkit::endpoint& to) override;


public:
	handler_direct( loader &ldr, listener* owner, const asts& bb, netkit::socket_type_e st );
	virtual ~handler_direct() { stop(); }

	/*virtual*/ str::astr desc() const { return str::astr(ASTR("direct")); }
	/*virtual*/ bool compatible(netkit::socket_type_e /*st*/) const
	{
		return true; // compatible with both tcp and udp
	}

	/*virtual*/ void handle_pipe(netkit::pipe* pipe) override;
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
	netkit::ipap udp_bind;

	bool socks5_allow_anon = false;

	bool allow_4 = true;
	bool allow_5 = true;
	bool allow_udp_assoc = true;
	bool allow_private = false;

	void handshake4(netkit::pipe* pipe);
	void handshake5(netkit::pipe* pipe);

	using sendanswer = std::function< void(netkit::pipe* pipe, rslt ecode) >;

	void worker(netkit::pipe* pipe, netkit::endpoint& inf, sendanswer answ);

public:
	handler_socks(loader& ldr, listener* owner, const asts& bb, const str::astr_view &st);
	virtual ~handler_socks() { stop(); }

	/*virtual*/ str::astr desc() const { return str::astr(ASTR("socks")); }
	/*virtual*/ bool compatible(netkit::socket_type_e st) const
	{
		return st == netkit::ST_TCP;
	}

	/*virtual*/ void handle_pipe(netkit::pipe* pipe) override;
};

#include "handler_ss.h"
#include "handler_http.h"
#ifdef _DEBUG
#include "debug/handler_dbg.h"
#endif // _DEBUG
