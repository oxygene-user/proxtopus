/*
    spinlock module
*/
#pragma once

#ifndef PROXTOPUS_PCH
#error "do not include this file without pch.h"
#endif

#ifdef _MSC_VER
#include <intrin.h>
#include <stdint.h>
#pragma warning(push)
#pragma warning(disable:4189) // 'val': local variable is initialized but not referenced
#endif
#ifdef __GNUC__
#include <x86intrin.h>
#endif
#ifdef __linux__
#include <pthread.h>
#include <unistd.h>
#endif

#ifndef IS_SINGLE_CORE
#define IS_SINGLE_CORE (false)
#endif

namespace spinlock
{
#if defined _WIN32
    inline void sleep()
    {
        _mm_pause();
    }
    inline void sleep(int ms)
    {
        Sleep(ms);
    }
#endif

    /* 
      This is not a thread id in the usual sense.This number cannot be passed to the operating system.
      However, this number is unique for each thread just like the thread id. Unlike the thread id,
      which has a size of up to 64 bits (on Linux, for example), this number in most cases will not exceed 16 bits.
    */
    size_t current_thread_uid();

#if defined(_MSC_VER)
#define SLINLINE __forceinline
#elif defined(GCC_OR_CLANG)
#define SLINLINE inline
#endif

#if defined(__linux__)
inline void sleep()
{
    sched_yield();
}
inline void sleep(int ms)
{
    if (0 == ms)
    {
        sched_yield();
        return;
    }
    struct timespec req;
    req.tv_sec = ms >= 1000 ? (ms / 1000) : 0;
    req.tv_nsec = (ms - req.tv_sec * 1000) * 1000000;

    // Loop until we've slept long enough
    do
    {
        // Store remainder back on top of the original required time
        if (0 != nanosleep(&req, &req))
        {
            /* If any error other than a signal interrupt occurs, return an error */
            if (errno != EINTR)
                return;
        }
        else
        {
            // nanosleep succeeded, so exit the loop
            break;
        }
    } while (req.tv_sec > 0 || req.tv_nsec > 0);
}
#endif

template<typename T> SLINLINE void atomic_set(volatile T &t, const T&v)
{
    if constexpr (sizeof(size_t) >= sizeof(T))
    {
        t = v; // no need to use interlocked* functions if sizeof var same as archbits
    }
    else
    {
        static_assert(sizeof(T) == 8);

#ifdef _WIN32
        _InterlockedExchange64((LONG64*)&t, v);
#else
        atomic_exchange_64(&t, v, __ATOMIC_SEQ_CST);
#endif
    }
}

template<typename T> SLINLINE T atomic_load(volatile T& t)
{
    if constexpr (sizeof(size_t) >= sizeof(T))
    {
        return t; // no need to use interlocked* functions if sizeof var same as archbits
    }
    else
    {
        static_assert(sizeof(T) == 8);

#ifdef _WIN32
        return InterlockedCompareExchange64((LONG64*)&t, 0, 0);
#else
        return __atomic_load(&t, __ATOMIC_SEQ_CST);
#endif
    }
}

template<typename T> SLINLINE void atomic_add(volatile T& t, T v)
{
#ifdef _WIN32
    if constexpr (sizeof(T) == 8)
    {
        _InterlockedAdd64((LONG64 *) & t, v);
    }
    else
    {
        static_assert(sizeof(T) == 4);
        _InterlockedAdd((LONG *) & t, v);
    }
#else
    __atomic_add_fetch(&t, v, __ATOMIC_SEQ_CST);
#endif
}

template<typename T> SLINLINE T atomic_increment(volatile T& t)
{
#ifdef _WIN32
    if constexpr (sizeof(T) == 8)
    {
        return _InterlockedIncrement64((LONG64*)&t);
    }
    else
    {
        static_assert(sizeof(T) == 4);
        return _InterlockedIncrement(&t);
    }
#else
    return __atomic_add_fetch(&t, 1, __ATOMIC_SEQ_CST);
#endif

}

template<typename T> SLINLINE T atomic_decrement(volatile T& t)
{
#ifdef _WIN32
    if constexpr (sizeof(T) == 8)
    {
        return _InterlockedDecrement64((LONG64*)&t);
    }
    else
    {
        static_assert(sizeof(T) == 4);
        return _InterlockedDecrement(&t);
    }
#else
    return __atomic_sub_fetch(&t, 1, __ATOMIC_SEQ_CST);
#endif

}

template<typename T> bool atomic_cas(volatile T& t, T expected, T desired)
{
#ifdef _WIN32
    if constexpr (sizeof(T) == 16)
    {
        return 0 != _InterlockedCompareExchange128((LONG64*)(&t), ((i64*)&desired)[1], ((i64*)&desired)[0], (LONG64*)&expected);

    } else if constexpr (sizeof(T) == 8)
    {
        return _InterlockedCompareExchange64((LONG64*)&t, desired, expected) == (LONG64)expected;
    }
    else
    {
        static_assert(sizeof(T) == 4);
        return _InterlockedCompareExchange((LONG*)&t, desired, expected) == (LONG)expected;
    }
#else
    if constexpr (sizeof(T) == 16)
    {
        //return __atomic_compare_exchange((__int128 *)&t, (__int128*)&expected, (const __int128*)&desired, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
        return __sync_bool_compare_and_swap((__int128*)&t, (__int128&)expected, (__int128&)desired);
    }
    else {
        return __atomic_compare_exchange(&t, &expected, &desired, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    }
#endif
}

template<typename T> bool atomic_cas_update_expected(volatile T& t, T &expected, const T &desired)
{
#ifdef _WIN32
    if constexpr (sizeof(T) == 16)
    {
        return 0 != _InterlockedCompareExchange128((LONG64*)(&t), ((i64*)&desired)[1], ((i64*)&desired)[0], (LONG64*)&expected);

    } else if constexpr (sizeof(T) == 8)
    {
        auto prevv = _InterlockedCompareExchange64((LONG64*)&t, desired, expected);
        if ((LONG64)expected != prevv)
        {
            expected = prevv;
            return false;
        }
        return true;
    }
    else
    {
        static_assert(sizeof(T) == 4);
        auto prevv = _InterlockedCompareExchange((LONG*)&t, desired, expected);
        if ((LONG)expected != prevv)
        {
            expected = prevv;
            return false;
        }
        return true;
    }
#else
    if constexpr (sizeof(T) == 16)
    {
        //return __atomic_compare_exchange((__int128 *)&t, (__int128*)&expected, (const __int128*)&desired, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
        if (__sync_bool_compare_and_swap((__int128*)&t, (__int128&)expected, (__int128&)desired))
            return true;
        tools::memcopy<16>(&expected, (const void*)&t);
        return false;
    }
    else
    {
        return __atomic_compare_exchange(&t, &expected, &desired, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    }
#endif
}

//////////////////////////////////////////////////////////////////////////
// reenterable spinlock
// many readers, writer wait and block new readers
// ACHTUNG! ACHTUNG! [read] then [write] lock in same thread leads to deadlock!!!

using rwlock = u64;
constexpr const rwlock lock_thread_mask = 0x000000FFFFFFFFFFull;
constexpr const rwlock lock_read_mask   = 0xFFFF000000000000ull;
constexpr const rwlock lock_read_value  = 0x0001000000000000ull;
constexpr const rwlock lock_write_mask  = 0x0000FF0000000000ull;
constexpr const rwlock lock_write_value = 0x0000010000000000ull;

SLINLINE void lock_write(volatile rwlock &lock)
{
	rwlock thread = current_thread_uid() & lock_thread_mask;
	if ((atomic_load(lock) & lock_thread_mask) == thread) // second lock same thread
	{
        atomic_add(lock, lock_write_value);
		return;
	}
	thread |= lock_write_value;

    // now wait for write lock released
    size_t spincount = 0;
	for(rwlock expected = lock;; ++spincount) // initial lock
	{
        expected &= lock_read_mask;
        rwlock newlock = expected | thread;

        if (atomic_cas_update_expected(lock, expected, newlock))
            break; // write lock was released

        if (IS_SINGLE_CORE || spincount > 10000)
        {
            sleep((spincount >> 17) & 0xff);
            expected = lock;
        }
        else
            sleep();
	}

    // if there are readers from current thread - deadlock:
    //      lock-write, lock-read, unlock-read, unlock-write => ok
    //      lock-read, lock-write ... => deadlock
	for (;; ++spincount)
	{
		if (0 == (lock & lock_read_mask)) // all readers gone // no need to use atomic_load here because we need masked value
			return;

        if (IS_SINGLE_CORE || spincount > 10000)
            sleep((spincount >> 17) & 0xff);
        else
            sleep();
    }
}

SLINLINE void lock_read(volatile rwlock&lock)
{
	rwlock thread = current_thread_uid() & lock_thread_mask;
	if ((atomic_load(lock) & lock_thread_mask) == thread)
	{
        atomic_add(lock, lock_read_value); // allow read_lock if already locked with write_lock for current thread
		return;
	}

    rwlock expected = lock; // allow read lock only if no write locks - thread and write parts are 0
	for (size_t spincount = 0;; ++spincount) // Initial lock
	{
        expected &= lock_read_mask;
        rwlock val = expected + lock_read_value;

        if (atomic_cas_update_expected(lock, expected, val))
            break; // read lock count increased

        if (IS_SINGLE_CORE || spincount > 10000)
        {
            sleep((spincount >> 17) & 0xff);
            expected = lock; // no need use atomic_load here due we need masked value
        }
        else
            sleep();
    }
}

SLINLINE bool try_lock_read(volatile rwlock &lock)
{
    rwlock thread = current_thread_uid() & lock_thread_mask;
    if ((atomic_load(lock) & lock_thread_mask) == thread)
    {
        atomic_add(lock, lock_read_value);
        return true;
    }

    rwlock expected = lock & lock_read_mask;
    rwlock val = expected + lock_read_value;
    return atomic_cas(lock, expected, val);
}


SLINLINE bool try_lock_write(volatile rwlock &lock)
{
	rwlock thread = current_thread_uid() & lock_thread_mask;
	if ((atomic_load(lock) & lock_thread_mask)==thread) // second lock
	{
        atomic_add(lock, lock_write_value);
		return true;
	}
	thread |= lock_write_value;
    return atomic_cas<rwlock>(lock, 0, thread);
}

SLINLINE void unlock_write(volatile rwlock &lock)
{
    rwlock thread = current_thread_uid() & lock_thread_mask;
    rwlock curlock = atomic_load(lock);

    if ((curlock & lock_thread_mask)!=thread)
        ERRORM(__FILE__, __LINE__, "bad call of unlock_write: current tid: $, locked tid: $", thread, (curlock & lock_thread_mask));

    if (0 == (curlock & lock_write_mask))
        ERRORM(__FILE__, __LINE__, "bad call of unlock_write: not locked for write ($)", HEX(0, curlock));

    rwlock val = curlock - lock_write_value;
	if(!(val & lock_write_mask)) // last lock - reset thread
		val &= lock_read_mask;

    atomic_set(lock, val);
}

SLINLINE void unlock_read(volatile rwlock &lock)
{
    ASSERT(lock & lock_read_mask, "bad call of unlock_read: not locked for read ($)", lock);
    atomic_add(lock, ~(lock_read_value - 1));
}

struct auto_lock_write
{
    volatile rwlock *lock;
    auto_lock_write(volatile rwlock & _lock ) : lock(&_lock)
    {
		lock_write(*lock);
    }
    ~auto_lock_write()
    {
        if (lock)
            unlock_write(*lock);
    }
    void unlock()
    {
        if (lock)
        {
            unlock_write(*lock);
            lock = nullptr;
        }
    }
};

struct auto_lock_read
{
    volatile rwlock*lock;
    auto_lock_read(volatile rwlock& _lock ) : lock(&_lock)
    {
        lock_read(*lock);
    }
    ~auto_lock_read()
    {
        if(lock)
			unlock_read(*lock);
    }
};

inline void simple_lock(volatile size_t &lock)
{
    for (; !atomic_cas<size_t>(lock, 0, 1);)
    {
        if (IS_SINGLE_CORE)
            sleep(0);
        else
            sleep();
    }
}

inline void simple_lock_spincount(volatile size_t& lock, size_t spincount)
{
    for (size_t sc = 0; !atomic_cas<size_t>(lock, 0, 1); ++sc)
    {
        if (IS_SINGLE_CORE || sc > spincount)
            sleep((sc >> 17) & 0xff);
        else
            sleep();
    }
}

inline bool try_simple_lock(volatile size_t &lock)
{
    return atomic_cas<size_t>(lock, 0, 1);
}


inline void simple_unlock(volatile size_t &lock)
{
    atomic_set<size_t>(lock, 0);
}

struct auto_simple_lock
{
    volatile size_t *lockvar;
    auto_simple_lock(volatile size_t& _lock, bool) : lockvar(&_lock)
    {
        if (!try_simple_lock(*lockvar))
            lockvar = nullptr;
    }
    auto_simple_lock(volatile size_t& _lock) : lockvar(&_lock)
    {
        simple_lock(*lockvar);
    }
    ~auto_simple_lock()
    {
        if (lockvar)
            simple_unlock(*lockvar);
    }
    bool is_locked() const { return lockvar != nullptr; }
    void lock( size_t& _lock)
    {
        if (lockvar) simple_unlock(*lockvar);
        lockvar = &_lock;
        simple_lock(*lockvar);
    }
    void unlock()
    {
        if (lockvar)
        {
            simple_unlock(*lockvar);
            lockvar = nullptr;
        }
    }
};

//////////////////////////////////////////////////////////////////////////

template <typename VARTYPE> class syncvar
{
    volatile mutable rwlock m_lock = 0;
    VARTYPE m_var = {};

    class read_accessor
    {
        const VARTYPE *var;
        const syncvar *host;
        friend class syncvar;
        read_accessor( const VARTYPE & _var, const syncvar *_host ): var(&_var), host(_host)
        {
        }
        read_accessor & operator = (const read_accessor &) = delete;
        read_accessor(const read_accessor &) = delete;
    public:
        read_accessor( read_accessor &&r ): var(r.var), host(r.host)
        {
            r.var = nullptr;
            r.host = nullptr;
        }
        ~read_accessor()
        {
            if (host)
                host->unlock_read();
        }
        read_accessor & operator = (read_accessor &&r)
        {
            if (host)
                host->unlock_read();
            var = r.var;
            host = r.host;
            r.var = nullptr;
            r.host = nullptr;
            return *this;
        }

        bool is_locked() const
        {
            return host != nullptr;
        }

        void unlock()
        {
            ASSERT (host != nullptr);
            host->unlock_read();
            var = nullptr;
            host = nullptr;
        }

        const VARTYPE &operator()()
        {
            ASSERT(var != nullptr && host != nullptr);
            return *var;
        }
    };

    class write_accessor
    {
        VARTYPE * var;
        const syncvar *host;
        friend class syncvar;
        write_accessor( VARTYPE * _var, const syncvar *_host ): var(_var), host(_host)
        {
        }
        write_accessor & operator = (const write_accessor &r) = delete;
        write_accessor(const write_accessor &r) = delete;
    public:
        write_accessor(): var(nullptr), host(nullptr) {}
        write_accessor( write_accessor &&r ): var(r.var), host(r.host)
        {
            r.var = nullptr;
            r.host = nullptr;
        }
        write_accessor & operator = ( write_accessor &&r )
        {
            if (host != nullptr)
                host->unlock_write();
            var = r.var;
            host = r.host;
            r.var = nullptr;
            r.host = nullptr;
            return *this;
        }
        ~write_accessor()
        {
            if (host != nullptr)
                host->unlock_write();
        }
        bool is_locked() const {return host != nullptr;}
        operator bool() const { return is_locked(); }
        void unlock()
        {
            ASSERT(host != nullptr);
            host->unlock_write();
            var = nullptr;
            host = nullptr;
        }


        VARTYPE &operator()()
        {
            ASSERT(var != nullptr && host != nullptr);
            return *var;
        }
    };


    friend class read_accessor;
    friend class write_accessor;

private:

    /**
    * Unlock variable (other threads can lock it)
    */
    void unlock_write() const
    {
        spinlock::unlock_write(m_lock);
    }
    void unlock_read() const
    {
        spinlock::unlock_read(m_lock);
    }

public:

    using READER = read_accessor;
    using WRITER = write_accessor;

public:


    /**
    * Constructor. Custom initialization for protected variable
    */
    explicit syncvar(const VARTYPE &v): m_var(v)
    {
    }
    /**
    * Constructor. Default initialization for protected variable
    */
    syncvar()
    {
    }
    /**
    * Destructor
    */
    ~syncvar()
    {
    }

    /**
    * Sync variable for read. Other threads can also lock this variable for read.
    * Current thread will wait for lock_read if there are some other thread waits for lock_write
    */

    read_accessor lock_read() const
    {
        spinlock::lock_read(m_lock);
        return read_accessor( m_var, this );
    }

    template<typename H> void lock_read(const H& h)
    {
        spinlock::lock_read(m_lock);
        h(m_var);
        spinlock::unlock_read(m_lock);
    }

    /**
    *  Lock variable for write. no any other thread can lock for read or write.
    */
    write_accessor lock_write()
    {
        spinlock::lock_write(m_lock);
        return write_accessor( &m_var, this );
    }
    write_accessor try_lock_write()
    {
        if (try_lock_write(m_lock))
            return write_accessor(&m_var, this);
        return write_accessor();
    }

    bool locked() const {return m_lock != 0;}
};

#if defined(_MSC_VER)
#pragma warning(pop)
#endif

} // namespace spinlock
