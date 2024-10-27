/*
    spinlock module
    (C) 2010-2015 BMV, ROTKAERMOTA (TOX: ED783DA52E91A422A48F984CAC10B6FF62EE928BE616CE41D0715897D7B7F6050B2F04AA02A1)
*/
#pragma once

#ifndef _SPINLOCK_LIST_INCLUDE_

#include "spinlock.h"

#if defined _MSC_VER
#pragma warning(push)
#pragma warning(disable:4324) // : structure was padded due to __declspec(align())
#endif

namespace spinlock
{
template<typename T> class
#ifdef _WIN32
__declspec(align(16))
#endif
spinlock_list_s
{
	struct
#ifdef _WIN32
		__declspec(align(16))
#endif
		pointer_t
	{
		T* ptr;
		long3264 count;
		// default to a null pointer with a count of zero
		pointer_t() : ptr(nullptr),count(0){}
		pointer_t(T* element, const long3264 c ) : ptr(element),count(c){}
		pointer_t(const volatile pointer_t& p) : ptr(p.ptr),count(p.count){}
	}
#ifdef _LINUX
		__attribute__((aligned(16)))
#endif
		;

	volatile pointer_t first;

    SLINLINE void add(T* element)
    {
        if (element)
        {
            pointer_t old_val(first);
            for (;;)
            {
                element->list_next = old_val.ptr;
                if (CAS2(first, old_val, pointer_t(element, old_val.count + 1))) break; // success - exit loop
            }
        }
    }

    T* get()
    {
        __try{
            pointer_t old_val(first);
            while (old_val.ptr)
            {
                T* next = old_val.ptr->list_next;
                if (CAS2(first, old_val, pointer_t(next, old_val.count + 1)))
                {
                    return(old_val.ptr); // success - exit loop
                }
            }
        }

#ifdef _WIN32
        __except (/*EXCEPTION_EXECUTE_HANDLER*/ 1){
            SLERROR("spinlock list get crush");
        }
#else
        catch (...){
            SLERROR("spinlock list get crush");
        }
#endif
        return(nullptr);
    }

public:
    spinlock_list_s() {}
	void clear(){ first.ptr=nullptr; }
    inline void push(T* element) { add(element); }
    inline T* pop() { return(get()); }
}
#ifdef _LINUX
__attribute__ (( aligned (16)))
#endif
;


} // namespace spinlock

#if defined _MSC_VER
#pragma warning(pop)
#endif

#endif