#pragma once


namespace ptr
{
	/*
		intrusive shared pointer

		example:
		shared_ptr<MyClass> p(new MyClass(...)), p2(p), p3=p;
		. . .
	*/

	template <class T> class shared_ptr // T must be public child of shared_object
	{
		T* object = nullptr;

		void unconnect()
		{
			if (object) T::dec_ref(object);
		}

		void connect(T* p)
		{
			object = p;
			if (object) object->add_ref();
		}

	public:
		shared_ptr() {}
		//shared_ptr(const T &obj):object(new T (obj)) {object->ref = 1;}
		shared_ptr(T* p) { connect(p); } // now safe todo: shared_ptr p1(obj), p2(obj);
		shared_ptr(const shared_ptr& p) { connect(p.object); }
		shared_ptr(shared_ptr&& p) :object(p.object) { p.object = nullptr; }

		shared_ptr& operator=(T* p)
		{
			if (p) p->add_ref(); // ref up - to correct self assign
			unconnect();
			object = p;
			return *this;
		}
		shared_ptr& operator=(const shared_ptr& p)
		{
			return *this = p.object;
		}

		shared_ptr& operator=(shared_ptr&& p)
		{
			unconnect();
			object = p.object;
			p.object = nullptr;
			return *this;
		}

		~shared_ptr() { unconnect(); }

		void swap(shared_ptr& p) { tools::swap(*this, p); }

		operator T* () const { return object; }
		T* operator->() const { return object; }

		T* get() { return object; }
		const T* get() const { return object; }

		// tricky methods; use only if you absolutely understand what you do
        T* _release() { T* rv = object; object = nullptr; return rv; }
        void _assign(T* t) { object = t; };

	};

	template<typename N = int> struct intref
	{
		N value = 0;

		intref& operator++()
		{
			++value;
			return *this;
		}
		intref& operator--()
		{
			--value;
			return *this;
		}

		bool operator()()
		{
			auto nv = --value;
			ASSERT(nv >= 0);
			return nv == 0;
		}
		bool is_multi() const
		{
			return value > 1;
		}
		bool is_new() const
		{
			return value == 0;
		}
	};

	using intref_sync = intref<std::atomic<signed_t>>;

	struct DELETER
	{
		template<typename T> static void kill(T* o)
		{
			delete o;
		}
	};

	struct FREER
	{
		template<typename T> static void kill(T* o)
		{
			free(o);
		}
	};

	struct RELEASER
	{
		template<typename T> static void kill(T* o)
		{
			o->release();
		}
	};

	template<typename REF, typename OKILLER = DELETER> class shared_object_t
	{
		mutable REF ref;

		shared_object_t(const shared_object_t&) = delete;
		void operator=(const shared_object_t&) = delete;
	public:
		shared_object_t() {}

		bool is_ref_new() const { return ref.is_new(); }
		bool is_multi_ref() const { return ref.is_multi(); }
		void add_ref() const { ++ref; }
		void dec_ref_no_check() const { --ref; }
		template <class T> static void dec_ref(T* object)
		{
			if (object->ref())
				OKILLER::kill(object);
		}
	};

	using shared_object = shared_object_t<intref<int>>;
	using sync_shared_object = shared_object_t<intref_sync>;
	template <typename KILLER> using sync_shared_object_ck = shared_object_t<intref_sync, KILLER>; // with custom killer

	// intrusive UNMOVABLE weak pointer
	// UNMOVABLE means that you cannot use memcpy to copy this pointer

	template<class OO> struct eyelet_s;
	template<class OO, class OO1 = OO> struct iweak_ptr
	{
		friend struct eyelet_s<OO>;
	private:
		iweak_ptr* prev = nullptr;
		iweak_ptr* next = nullptr;
		OO* oobject = nullptr;

	public:

		iweak_ptr() {}
		iweak_ptr(const iweak_ptr& hook)
		{
			if (hook.get()) const_cast<OO*>(static_cast<const OO*>(hook.get()))->hook_connect(this);
		}

		iweak_ptr(OO1* ob)
		{
			if (ob) ((OO*)ob)->OO::hook_connect(this);
		}
		~iweak_ptr()
		{
			unconnect();
		}

		void unconnect()
		{
			if (oobject) oobject->hook_unconnect(this);
		}

		iweak_ptr& operator = (const iweak_ptr& hook)
		{
			if (hook.get() != get())
			{
				unconnect();
				if (hook.get()) const_cast<OO*>(hook.get())->hook_connect(this);
			}
			return *this;
		}

		iweak_ptr& operator = (OO1* obj)
		{
			if (obj != get())
			{
				unconnect();
				if (obj) obj->OO::hook_connect(this);
			}
			return *this;
		}

		explicit operator bool() { return get() != nullptr; }

		template<typename OO2> bool operator==(const OO2* obj) const { return oobject == ptr_cast<const OO2*>(obj); }

		OO1* operator()() { return static_cast<OO1*>(oobject); }
		const OO1* operator()() const { return static_cast<const OO1*>(oobject); }

		operator OO1* () const { return static_cast<OO1*>(oobject); }
		OO1* operator->() const { return static_cast<OO1*>(oobject); }

		OO1* get() { return static_cast<OO1*>(oobject); }
		const OO1* get() const { return static_cast<OO1*>(oobject); }

		bool expired() const { return get() == nullptr; }
	};

	template<class OO> struct eyelet_s
	{
		iweak_ptr<OO>* first = nullptr;

		eyelet_s() {}
		~eyelet_s()
		{
			iweak_ptr<OO>* f = first;
			for (; f;)
			{
				iweak_ptr<OO>* next = f->next;

				f->oobject = nullptr;
				f->prev = nullptr;
				f->next = nullptr;

				f = next;
			}
		}

		void connect(OO* object, iweak_ptr<OO, OO>* hook)
		{
			if (hook->get()) hook->get()->hook_unconnect(hook);
			hook->oobject = object;
			hook->prev = nullptr;
			hook->next = first;
			if (first) first->prev = hook;
			first = hook;
		}

		void    unconnect(iweak_ptr<OO, OO>* hook)
		{
#ifdef _DEBUG
			iweak_ptr<OO>* f = first;
			for (; f; f = f->next)
			{
				if (f == hook) break;
			}
			ASSERT(f == hook, "foreigner hook!!!");

#endif
			if (first == hook)
			{
				ASSERT(first->prev == nullptr);
				first = hook->next;
				if (first)
				{
					first->prev = nullptr;
				}
				hook->next = nullptr;
			}
			else
			{
				ASSERT(hook->prev != nullptr);
				hook->prev->next = hook->next;
				if (hook->next) { hook->next->prev = hook->prev; hook->next = nullptr; };
				hook->prev = nullptr;
			}
			hook->oobject = nullptr;
		}
	};

}

#define DECLARE_EYELET( obj ) private: ptr::eyelet_s<obj> _ptr_eyelet; public: \
	template<class OO1> void hook_connect( ptr::iweak_ptr<obj, OO1> * hook ) { _ptr_eyelet.connect(this, reinterpret_cast<ptr::iweak_ptr<obj>*>(hook)); } \
	template<class OO1> void hook_unconnect( ptr::iweak_ptr<obj, OO1> * hook ) { _ptr_eyelet.unconnect(reinterpret_cast<ptr::iweak_ptr<obj>*>(hook)); } private:

