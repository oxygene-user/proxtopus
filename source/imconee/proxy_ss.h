#pragma once

inline std::span<u8> str2span(std::string& s)
{
	return std::span<u8>(reinterpret_cast<u8*>(s.data()), s.length());
}

inline std::span<const u8> str2span(const std::string &s)
{
	return std::span<const u8>(reinterpret_cast<const u8*>(s.data()), s.length());
}
inline std::span<const u8> str2span(const std::string_view& s)
{
	return std::span<const u8>(reinterpret_cast<const u8*>(s.data()), s.length());
}

inline std::string_view span2str(const buffer& s)
{
	return std::string_view(reinterpret_cast<const char*>(s.data()), s.size());
}
inline std::string_view span2str(const std::span<const u8>& s)
{
	return std::string_view(reinterpret_cast<const char*>(s.data()), s.size());
}

class proxy_shadowsocks : public proxy
{
	ss::core core;

public:
	proxy_shadowsocks(loader& ldr, const str::astr& name, const asts& bb);
	/*virtual*/ ~proxy_shadowsocks() {}

	netkit::pipe_ptr prepare(netkit::pipe_ptr pipe_to_proxy, netkit::endpoint& addr) const;
};

