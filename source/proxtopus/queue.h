/*
    spinlock module
    (C) 2010-2015 BMV, ROTKAERMOTA (TOX: ED783DA52E91A422A48F984CAC10B6FF62EE928BE616CE41D0715897D7B7F6050B2F04AA02A1)
*/
#pragma once

#ifndef _SPINLOCK_QUEUE_INCLUDE_

#include "list.h"

namespace spinlock
{

struct defallocator
{
    static void *ma( size_t sz ) { return malloc(sz); }
    static void mf( void *ptr ) { free(ptr); }
};

// T must be a pointer

template< typename T, typename A = defallocator > class
#ifdef _WIN32
__declspec(align(16))
#endif
spinlock_queue_s
{
	struct node_t;

	struct WIN32ALIGN pointer_t
	{
		node_t* ptr;
		long3264 count;
		pointer_t() : ptr(nullptr),count(0){};
		pointer_t(node_t* node, const long3264 c ) : ptr(node),count(c){}
		pointer_t(const volatile pointer_t& p) : ptr(p.ptr),count(p.count){}
        pointer_t& operator=(const volatile pointer_t& p){ ptr=p.ptr; count=p.count; return(*this); }
	}
#ifdef _LINUX
	__attribute__((aligned(16)))
#endif
		;

	struct node_t : public pointer_t
	{
        union
        {
			T value;
			node_t* list_next; // used in spinlock_list_s
        };
        node_t() {}
	};

	volatile pointer_t Head;
	volatile pointer_t Tail;
	spinlock_list_s<node_t> freenodes;
	
	node_t* get_node()
	{
		node_t* result = freenodes.pop();
		if (!result)
			result = (node_t*)A::ma(sizeof(node_t));
		
		if (result)
		{
			result->ptr = nullptr;
			result->count = 0;
		}
		return result;
 	}
	void free_node(node_t* node)
	{
		freenodes.push(node);
	}

public:	

    enum
    {
        ABLOCK_SIZE = sizeof( node_t )
    };

	spinlock_queue_s()
	{
		node_t* n = get_node();
		n->value = {};
		Head.ptr = Tail.ptr = n;
	}
	~spinlock_queue_s()
	{
		// remove the dummy head
		SLASSERT(Head.ptr==Tail.ptr);
        free_node(Head.ptr);

        while (node_t* node=freenodes.pop())
            A::mf(node);
	}

	// insert items of class T in the back of the queue
	// items of class T must implement a default and copy constructor
	// Enqueue method
	SLINLINE bool enqueue(const T& t)
	{
		node_t* n = get_node(); 
		if (!n) return false;
		n->value = t;

		for(;;)
		{
			// Read Tail.ptr and Tail.count together
			pointer_t tail(Tail);

			bool is_null_tail = (nullptr==tail.ptr); 
			
			// Read next ptr and count fields together
			pointer_t next( (is_null_tail)? nullptr : tail.ptr->ptr,
							(is_null_tail)? 0 : tail.ptr->count ) ;

			// Are tail and next consistent?
			if(tail.count == Tail.count && tail.ptr == Tail.ptr)
			{
				if(nullptr == next.ptr) // Was Tail pointing to the last node?
				{
					// Try to link node at the end of the linked list										
					pointer_t p(n, next.count + 1);
					if(CAS2<pointer_t>( *tail.ptr, next, p ) )
						return true;

				} else // Tail was not pointing to the last node
				{
					// Try to swing Tail to the next node
					pointer_t p(next.ptr, tail.count + 1);
					CAS2(Tail, tail, p);
				}

			}
		}
	}

	SLINLINE bool push(const T& t){ return(enqueue(t)); };

	// remove items of class T from the front of the queue
	// items of class T must implement a default and copy constructor
	// Dequeue method
	SLINLINE bool dequeue(T &t)
	{
		pointer_t head;
		// Keep trying until Dequeue is done
		for(;;)
		{
			// Read Head
			head = Head;
			// Read Tail
			pointer_t tail(Tail);

			if(head.ptr == nullptr)
				return false; // queue is empty

			// Read Head.ptr->next
			pointer_t next(*head.ptr);

			// Are head, tail, and next consistent
			if(head.count == Head.count && head.ptr == Head.ptr)
			{
				if(head.ptr == tail.ptr) // is tail falling behind?
				{
					if(nullptr == next.ptr)
						return false; // queue is empty cannot deque

					pointer_t p(next.ptr, tail.count + 1);
					CAS2(Tail, tail, p); // Tail is falling behind. Try to advance it
					}

				else // no need to deal with tail
				{
                    if(nullptr != next.ptr)
                    {
                        // read value before CAS otherwise another deque might try to free the next node
                        t = next.ptr->value;

                        // try to swing Head to the next node
						pointer_t p(next.ptr, head.count + 1);
                        if(CAS2(Head, head, p))
                        {
                            // It is now safe to free the old dummy node
                            free_node(head.ptr);
                            // queue was not empty, deque succeeded
                            return true;
                        }
                    }
				}
			}
		}
	}

	SLINLINE bool try_pop(T &t){ return(dequeue(t)); };
}
#ifdef _LINUX
__attribute__((aligned(16)))
#endif
;

} // namespace spinlock

#endif