#include <cstdint>
#include <cstddef>
#include <map>
#include <sstream>
#include <string>
#include <string_view>
#include "HTTP.h"
#include "quiet.h"

extern "C" int LLVMFuzzerInitialize (int *, char ***)
{
	QuietLogs ();
	return 0;
}

extern "C" int LLVMFuzzerTestOneInput (const uint8_t * data, size_t size)
{
	if (size > 16 * 1024) return -1;
	std::string_view in ((const char *)data, size);
	(void)i2p::http::UrlDecode (in, false);
	(void)i2p::http::UrlDecode (in, true);
	{
		std::istringstream is {std::string (in)};
		std::ostringstream os;
		(void)i2p::http::MergeChunkedResponse (is, os);
	}
	i2p::http::URL url;
	if (!url.parse (in)) return -1;
	(void)url.is_i2p ();
	(void)url.to_string ();
	(void)url.to_string (true);
	std::map<std::string, std::string> params;
	if (url.parse_query (params)) url.create_query (params);
	return 0;
}
