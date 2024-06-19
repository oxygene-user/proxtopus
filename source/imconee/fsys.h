#pragma once

std::wstring get_start_path();
std::wstring get_path(const std::wstring& full_file_path);

void path_simplify(std::wstring& path);
std::wstring path_fix(const std::wstring& path);
std::wstring path_concat(const std::wstring_view &path, const std::wstring_view &fn);
bool load_buf(const std::wstring& fn, std::vector<u8>& b);
void save_buf(const std::wstring& fn, const std::string& b);

std::wstring  get_exec_full_name();
void  set_start_path(std::wstring& wd, std::wstring* exename = nullptr);
inline void set_start_path()
{
	std::wstring wd;
	set_start_path(wd);
}
