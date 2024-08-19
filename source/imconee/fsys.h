#pragma once

#ifdef _MSC_VER
using FN = str::wstr;
using FNview = str::wstr_view;
using FNc = wchar;
inline FN& tofn(str::wstr& s) { return s; }
inline const FN& tofn(const str::wstr& s) { return s; }
#define MAKEFN WSTR
#elif defined __GNUC__
using FN = str::astr;
using FNview = str::astr_view;
using FNc = char;
#define MAKEFN ASTR
inline FN tofn(const str::wstr& s) { return str::to_utf8(s); }
#endif

FN get_start_path();
FN get_path(const FN& full_file_path);

void path_simplify(FN& path);
FN path_fix(const FN& path);
FN path_concat(const FNview &path, const FNview &fn);
bool load_buf(const FN& fn, buffer& b);
void save_buf(const FN& fn, const str::astr& b);

FN  get_exec_full_name();
void  set_start_path(FN& wd, FN* exename = nullptr);
inline void set_start_path()
{
	FN wd;
	set_start_path(wd);
}
