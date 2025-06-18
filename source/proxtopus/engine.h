#pragma once

#define ENOUGH_ACCEPTORS_COUNT 10
#define BRIDGE_BUFFER_SIZE (65536*2)

struct slot_statistics
{
    slot_statistics(signed_t inatime) :inactive_start(inatime) {}
    signed_t inactive_start = 0;
    bool one_sec_inactive = false;
#if DEEP_SLOT_TRACE
    size_t uid = tools::unique_id();
#endif
};

#if DEEP_SLOT_TRACE
struct deep_tracer
{
    static bool deep_trace_enabled;

    struct slotrec
    {
        std::vector<str::astr> log;
    };

    struct trace_rec
    {
        trace_rec(signed_t t) :time(t) {}
        signed_t time;
        size_t tid;
        size_t utid;
        size_t numlines = 0;
        std::map<size_t, slotrec> logs;
    };
    std::vector<trace_rec> recs;
    signed_t cur_thread_id = 0;
    signed_t cur_thread_uid = 0;
    size_t cur_slot_uid = 0;
    size_t traceuid = tools::unique_id();

    void set_current_slot(size_t uid)
    {
        cur_slot_uid = uid;
    }

    void set_current_thread();

    template <typename... T> void log(const char* s, const T&... args) {

        if (!deep_trace_enabled)
            return;

        signed_t ct = chrono::ms();

        trace_rec& rec = recs.empty() || recs[recs.size() - 1].time < ct ? recs.emplace_back(ct) : recs[recs.size() - 1];
        rec.tid = cur_thread_id;
        rec.utid = cur_thread_uid;

        slotrec& sr = rec.logs[cur_slot_uid];

        str::astr& sout = sr.log.emplace_back();
        str::impl_build_string(sout, s, args...);
    }
    void save_log();

};
#endif

class engine
{
	lcoll listners;
	api_collection_uptr<proxy> prox;

    std::mutex mtx;
    std::condition_variable cv;

	volatile size_t num_acceptors = 0;
	volatile size_t check_acceptors = 0;
	volatile size_t current_absorber = 0;

	struct tcp_pipe_and_handler
	{
        handler* h;
		netkit::tcp_pipe* pipe;
	};

    struct bridge_ready
    {
        netkit::pipe* pipe1;
		netkit::pipe* pipe2;
		slot_statistics* stat;
    };

	alignas(8) tools::bucket<tcp_pipe_and_handler> newpipes;
	alignas(8) tools::bucket<bridge_ready> ready_bridges;

	void acceptor();

    struct bridged
    {
        std::unique_ptr<slot_statistics> stat;
        netkit::pipe_ptr pipe1;
        netkit::pipe_ptr pipe2;
        u64 mask1 = 0;
        u64 mask2 = 0;
#if DEEP_SLOT_TRACE
        deep_tracer* tracer = nullptr;
#endif
#ifdef LOG_TRAFFIC
        traffic_logger loger;
#endif

        void clear()
        {
            pipe1 = nullptr;
            pipe2 = nullptr;
            mask1 = 0;
            mask2 = 0;
            stat.reset();
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
            SLOT_SKIPPED,
            SLOT_PROCESSED,
            SLOT_PROCESSED_HIGHLOAD,
        };

        process_result process(tools::circular_buffer_extdata& data, netkit::pipe_waiter::mask& masks); // returns: -1 - dead slot, 0 - slot not processed, 1 - slot processed

    };
    class tcp_processing_thread DST( : public deep_tracer )
    {
        signed_t name_wrk = -1;
        signed_t numslots = 0;
        netkit::pipe_waiter waiter;
        std::array<bridged, MAXIMUM_SLOTS> slots;
        std::unique_ptr<tcp_processing_thread> next;

        volatile bool waiting = false;

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

        tcp_processing_thread(netkit::pipe* pipe1, netkit::pipe* pipe2)
        {
            numslots = 1;
            slots[0].pipe1 = pipe1;
            slots[0].pipe2 = pipe2;
#if DEEP_SLOT_TRACE
            slots[0].stat.reset(NEW slot_statistics(chrono::ms()));
#endif

            spinlock::atomic_increment(glb.numtcp);
        }
        ~tcp_processing_thread();

        signed_t get_numslots() const
        {
            return numslots;
        }
        void signal()
        {
            if (waiting)
                waiter.signal();
        }
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
        bool tick(tools::circular_buffer_extdata &data); // returns false to stop
    };

    volatile spinlock::rwlock lock_tcp_list = 0;
    std::unique_ptr<tcp_processing_thread> tcps; // list of tcp threads

    bool has_absorber() const
    {
        return current_absorber != 0;
    }
    bool acquire_absorber_status(const tcp_processing_thread* th)
    {
        size_t thptr = reinterpret_cast<size_t>(th);
        if (thptr == current_absorber)
            return true;
        return spinlock::atomic_cas<size_t>(current_absorber, 0, thptr);
    }
    bool release_absorber_status(const tcp_processing_thread* th, bool full_reason);
    bool is_absorber_status(const tcp_processing_thread* th)
    {
        size_t thptr = reinterpret_cast<size_t>(th);
        return thptr == current_absorber;
    }
    bool bridge_absorb(bridged& br)
    {
        return ready_bridges.get([&br](bridge_ready& brr) {
            br.pipe1._assign(brr.pipe1);
            br.pipe2._assign(brr.pipe2);
            br.stat.reset(brr.stat);
#if DEEP_SLOT_TRACE
            br.tracer->set_current_slot(br.stat->uid);
            br.tracer->log("absorbed");
#endif
            });
    }
    bool bridge_alienation(bridged& br)
    {
        return ready_bridges.put([&br](bridge_ready& brr) {
            brr.pipe1 = br.pipe1._release();
            brr.pipe2 = br.pipe2._release();
            DST(br.tracer->log("alienation"));
            brr.stat = br.stat.release();
            });
    }
    bool bridge_alienation(netkit::pipe* pipe1, netkit::pipe* pipe2)
    {
        return ready_bridges.put([&](bridge_ready& brr) {
            brr.pipe1 = pipe1;
            brr.pipe2 = pipe2;
#if DEEP_SLOT_TRACE
            brr.stat = NEW slot_statistics(chrono::ms());
#else
            brr.stat = nullptr;
#endif
        });
    }

    void absorber_signal()
    {
        if (tcp_processing_thread* absorber = reinterpret_cast<tcp_processing_thread*>(current_absorber))
            absorber->signal();
    }
    void release_tcp(tcp_processing_thread* udp_wt);

public:

	int exit_code = EXIT_OK;

	engine();
	~engine();

	bool heartbeat(); // called once per second

	const proxy* find_proxy(const str::astr_view& pn) const
	{
		for (auto& p : prox)
			if (p->get_name() == pn)
				return p.get();
		return nullptr;
	}

	const lcoll& l() const { return listners; }
	const api_collection_uptr<proxy>& p() const { return prox; }

	void new_tcp_pipe(handler* h, netkit::tcp_pipe* p); // new incoming tcp connection // add pipe to dispatch bucket, so free acceptor will handle it
	void wake_up_acceptors()
	{
		check_acceptors = num_acceptors;
		cv.notify_all();
	}

    void bridge(netkit::pipe_ptr&& pipe1, netkit::pipe_ptr&& pipe2); // either does job in current thread or forwards job to another thread with same endpoint

};

inline const proxy* loader::find_proxy(const str::astr_view& pn) const
{
	return e->find_proxy(pn);
}
