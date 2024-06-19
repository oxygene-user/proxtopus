#include "pch.h"

/* botan stubs */

namespace Botan
{
	void assertion_failure(const char* expr_str,
		const char* assertion_made,
		const char* func,
		const char* file,
		int line)
	{
		ERRORM(file, line, "assertion (%s) (%s) (%s)", assertion_made, func, expr_str);
	}

	void throw_invalid_argument(const char* /*message*/,
		const char* /*func*/,
		const char* /*file*/)
	{
		SMART_DEBUG_BREAK;
	}

	void throw_invalid_state(const char* /*expr*/,
		const char* /*func*/,
		const char* /*file*/)
	{
		SMART_DEBUG_BREAK;
	}


} // namespace Botan