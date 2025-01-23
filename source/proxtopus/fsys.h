#pragma once

#define MAX_PATH_LENGTH 4096

#ifdef _MSC_VER
using FN = str::wstr;
using FNview = str::wstr_view;
using FNc = wchar;
inline FN& tofn(str::wstr& s) { return s; }
inline const FN& tofn(const str::wstr& s) { return s; }
inline const FN tofn(const str::astr_view& s) { return str::from_utf8(s); }
inline signed_t fnlen(const FN& fn) { return wcslen(fn.c_str()); }
#define MAKEFN WSTR
#elif defined __GNUC__
using FN = str::astr;
using FNview = str::astr_view;
using FNc = char;
#define MAKEFN ASTR
inline FN tofn(const str::wstr& s) { return str::to_utf8(s); }
inline const FN& tofn(const str::astr& s) { return s; }
inline const FNview& tofn(const str::astr_view& s) { return s; }
inline signed_t fnlen(const FN& fn) { return strlen(fn.c_str()); }
#endif

str::astr path_print_str(const FN& path);

FN get_start_path();
FN get_path(const FN& full_file_path);
FN get_name(const FN& full_file_path);

void path_simplify(FN& path, bool make_full);
FN path_fix(const FN& path);
FN path_concat(const FNview &path, const FNview &fn);
FN path_concat(const FNview& path1, const FNview& path2, const FNview& fn);
void path_append(FN& path, const FNview& fn);
bool load_buf(const FN& fn, buffer& b);
void save_buf(const FN& fn, const str::astr& b);

bool is_path_exists(const FNview& path);
bool is_file_exists(const FN& fname);



FN  get_exec_full_name();
void  set_start_path(FN& wd, FN* exename = nullptr);
inline void set_start_path()
{
	FN wd;
	set_start_path(wd);
}
