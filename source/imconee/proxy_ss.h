#pragma once

inline std::span<const u8> str2span(const std::string &s)
{
	return std::span<const u8>(reinterpret_cast<const u8*>(s.data()), s.length());
}
inline std::span<const u8> str2span(const std::string_view& s)
{
	return std::span<const u8>(reinterpret_cast<const u8*>(s.data()), s.length());
}

inline std::string_view span2str(const std::vector<u8>& s)
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
	proxy_shadowsocks(loader& ldr, const std::string& name, const asts& bb);
	/*virtual*/ ~proxy_shadowsocks() {}

	netkit::pipe_ptr prepare(netkit::pipe_ptr pipe_to_proxy, const netkit::endpoint& addr) const;
};

