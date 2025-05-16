#pragma once

#include <vector>
#include <span>
#if 0
#include <sstream>
#include <exception>
#include <optional>
#include <cmath>
#include <numbers>
#include <memory>

#ifdef _NIX
#include <stdint.h>
#include <memory.h>
#endif
#endif

#include "mem.h"

namespace Botan
{
	void secure_scrub_memory(void* ptr, size_t n);

	//template <typename T> using secure_vector = std::vector<T>;
	template <typename T> struct secure_vector;
	template<> struct secure_vector<uint32_t> : public std::vector<uint32_t> {
		template <typename T2, typename T3> secure_vector(const T2& t, const T3& t2) : std::vector<uint32_t>(t, t2) {}
		secure_vector() {}
		secure_vector(size_t fill_cnt) :std::vector<uint32_t>(fill_cnt) {}
	};
	template<> struct secure_vector<uint64_t> : public std::vector<uint64_t> {
		template <typename T2, typename T3> secure_vector(const T2& t, const T3& t2) : std::vector<uint64_t>(t, t2) {}
		secure_vector() {}
		secure_vector(size_t fill_cnt) :std::vector<uint64_t>(fill_cnt) {}
	};
	/*
	template<> struct secure_vector<uint8_t> : public std::vector<uint8_t> {
		template <typename T2, typename T3> secure_vector(const T2& t, const T3& t2) : std::vector<uint8_t>(t, t2) {}
		secure_vector() {}
		secure_vector(size_t fill_cnt) :std::vector<uint8_t>(fill_cnt) {}
		void zeroise()
		{
			memset(data(), 0, size());
		}
	};
	*/
	template<> struct secure_vector<uint8_t> {
		secure_vector() :buf((uint8_t*)MA(32)), cap(32) {}
		~secure_vector() {
			ma::mf(buf);
		}
		secure_vector(const secure_vector& ov) :sz(ov.sz)
		{
			cap = capsize(true, ov.sz);
			buf = (uint8_t*)MA(cap);
			memcpy(buf, ov.buf, ov.sz);
		}
		secure_vector(secure_vector&& ov) noexcept
		{
			buf = ov.buf;
			cap = ov.cap;
			sz = ov.sz;

			ov.buf = nullptr;
			ov.cap = 0;
			ov.sz = 0;
		}

		static size_t capsize(bool new_alloc, size_t sz)
		{
			if (new_alloc)
				return sz;
			return (sz >> 5) * 48 + 32;
			//return (sz + 31) & (~31);
		}

		explicit secure_vector(size_t isize) {
			sz = isize;
			cap = capsize(true, isize);
			buf = (uint8_t*)MA(cap);
			memset(buf, 0, isize);
		}

		/*
		explicit secure_vector(size_t sz, size_t cap):sz(sz),cap(cap) {
			buf = (uint8_t*)MA(cap);
			zeroise();
		}
		*/


		secure_vector(const uint8_t* ds, const uint8_t* de)
		{
			sz = de - ds;
			cap = capsize(true, sz);
			buf = (uint8_t*)MA(cap);
			memcpy(buf, ds, sz);
		}
		template<typename Iter> secure_vector(const Iter& bgn, const Iter& end)
		{
			sz = end - bgn;
			cap = capsize(true, sz);
			buf = (uint8_t*)MA(cap);
			memcpy(buf, &*bgn, sz);
		}

		template<typename Iter> void assign(const Iter& bgn, const Iter& end)
		{
			sz = end - bgn;
			if (sz <= cap)
			{
				memcpy(buf, &*bgn, sz);
			}
			else
			{
				cap = capsize(true, sz);
				buf = (uint8_t*)MRS(buf, cap, 0);
				memcpy(buf, &*bgn, sz);
			}
		}

		secure_vector& operator=(const secure_vector& ov)
		{
			if (cap >= ov.sz)
			{
				memcpy(buf, ov.buf, ov.sz);
				sz = ov.sz;
				return *this;
			}

			sz = ov.sz;
			cap = capsize(true, ov.sz);
			buf = (uint8_t*)MRS(buf, cap, 0);
			memcpy(buf, ov.buf, ov.sz);

			return *this;
		}
		secure_vector& operator=(secure_vector&& ov) noexcept
		{
			secure_scrub_memory(buf, sz);
			ma::mf(buf);

			buf = ov.buf;
			cap = ov.cap;
			sz = ov.sz;

			ov.buf = nullptr;
			ov.cap = 0;
			ov.sz = 0;

			return *this;
		}

		bool operator <(const secure_vector& ov) const
		{
			if (sz < ov.sz)
				return memcmp(buf, ov.buf, sz) <= 0;
			return memcmp(buf, ov.buf, ov.sz) < 0;
		}

		using pointer = uint8_t*;
		using const_pointer = const uint8_t*;
		using size_type = size_t;
		using iterator = uint8_t*;
		using const_iterator = const uint8_t*;
		using value_type = uint8_t;

		uint8_t* begin() { return buf; }
		uint8_t* end() { return buf + sz; }
		const uint8_t* begin() const { return buf; }
		const uint8_t* end() const { return buf + sz; }
		const uint8_t* cbegin() const { return buf; }
		const uint8_t* cend() const { return buf + sz; }

		uint8_t* data() { return buf; }
		const uint8_t* data() const { return buf; }
		size_t size() const { return sz; }

		uint8_t& operator[](size_t index) { return buf[index]; }
		const uint8_t& operator[](size_t index) const { return buf[index]; }

		std::span<const uint8_t> span() const { return std::span(data(), size()); }
		//operator std::span<const uint8_t>() const { return std::span(data(), size()); }

		void replace(size_t off, size_t cnt, const std::span<const uint8_t>& d)
		{
			if (cnt == d.size())
			{
				// no need shift
				memcpy(buf + off, d.data(), cnt);
				return;
			}
			if (cnt > d.size())
			{
				// no need allocate
				memcpy(buf + off, d.data(), d.size());
				size_t shrink_size = cnt - d.size();
				memcpy(buf + off + d.size(), buf + off + cnt, sz - off - cnt);
				sz -= shrink_size;
				return;
			}

			// d.size greater then cnt
			// may be need to reallocate

			size_t grow_size = d.size() - cnt;
			if (sz + grow_size > cap)
			{
				cap = capsize(false, sz + grow_size);
				uint8_t* nb = (uint8_t*)MA(cap);
				memcpy(nb, buf, off);
				memcpy(nb + off, d.data(), d.size());
				memcpy(nb + off + d.size(), buf + off + cnt, sz - off - cnt);
				ma::mf(buf);
				buf = nb;
			}
			else
			{
				memmove(buf + off + d.size(), buf + off + cnt, sz - off - cnt);
				memcpy(buf + off, d.data(), d.size());
			}
			sz += grow_size;

		}

		secure_vector& operator+=(uint8_t c) {

			if (1 + sz <= cap)
			{
				buf[sz] = c;
				++sz;
				return *this;
			}

			cap = capsize(false, sz + 1);
			buf = (uint8_t*)MRS(buf, cap, sz);
			buf[sz] = c;
			++sz;
			return *this;
		}
		secure_vector& operator+=(char c) { *this += (uint8_t)c; return *this; }

		secure_vector& operator+=(const std::span<const uint8_t>& in) {

			if (in.size() + sz <= cap)
			{
				memcpy(buf + sz, in.data(), in.size());
				sz += in.size();
				return *this;
			}

			size_t nsz = sz + in.size();
			cap = capsize(sz == 0, nsz);
			buf = (uint8_t*)MRS(buf, cap, sz);
			memcpy(buf + sz, in.data(), in.size());
			sz += in.size();

			return *this;
		}

		secure_vector& operator+=(const std::pair<const uint8_t*, size_t>& in) {

			return *this += std::span<const uint8_t>(in.first, in.second);
		}

		//secure_vector& operator+=(const std::vector<uint8_t>& in) {
			//return *this += std::span<const uint8_t>(in);
		//}

		void push_back(uint8_t b)
		{
			(*this) += b;
		}

		uint8_t back() const
		{
			return buf[sz - 1];
		}

		void clear()
		{
	#ifdef _DEBUG
			memset(buf, 0xab, sz);
	#else
			secure_scrub_memory(buf, sz);
	#endif
			sz = 0;
		}

		void clear_fast()
		{
			sz = 0;
		}

		/*
		void erase(size_t szerase) // erase from begin
		{
			memcpy( buf, buf + szerase, sz - szerase );
			sz -= szerase;
		}
		*/

		bool empty() const { return sz == 0; }

		void resize(size_t nsz, bool allow_uninitialized = false)
		{
			if (nsz <= cap)
			{
				sz = nsz;
				return;
			}

			cap = capsize(sz == 0, nsz);
			buf = (uint8_t*)MRS(buf, cap, sz);
			if (!allow_uninitialized && sz == 0)
				memset(buf, 0, nsz);
			sz = nsz;
		}

		void reserve(size_t new_cap_size)
		{
			if (new_cap_size > cap)
			{
				cap = capsize(sz == 0, new_cap_size);
				buf = (uint8_t*)MRS(buf, cap, sz);
			}
		}
        void reserve(size_t new_cap_size, size_t keep_data)
        {
			if (keep_data > sz)
				keep_data = sz;

            if (new_cap_size > cap)
            {
                cap = capsize(keep_data == 0, new_cap_size);
                buf = (uint8_t*)MRS(buf, cap, keep_data);
            }
        }

		inline void zeroise()
		{
			memset(buf, 0, sz);
		}

		uint8_t* buf;
		size_t sz = 0, cap;
	};

	inline void resize(secure_vector<uint8_t>& v, size_t sz)
	{
		v.resize(sz, true);
	}
	template<typename VEC> inline void resize(VEC& v, size_t sz)
	{
		v.resize(sz);
	}

} // namespace Botan

using buffer = Botan::secure_vector<uint8_t>;
