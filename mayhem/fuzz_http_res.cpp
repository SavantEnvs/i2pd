#include <cstdint>
#include <cstddef>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>
#include "HTTP.h"
#include "Gzip.h"
#include "quiet.h"

extern "C" int LLVMFuzzerInitialize (int *, char ***)
{
	QuietLogs ();
	return 0;
}

extern "C" int LLVMFuzzerTestOneInput (const uint8_t * data, size_t size)
{
	if (size > 64 * 1024) return -1;
	std::string_view in ((const char *)data, size);
	i2p::http::HTTPRes res;
	int r = res.parse (in);
	if (r <= 0) return -1;
	(void)res.content_length ();
	(void)res.get_header ("Content-Type");
	bool chunked = res.is_chunked ();
	bool gz = res.is_gzipped ();
	std::string body (in.substr (r));
	if (chunked)
	{
		std::istringstream is (body);
		std::ostringstream os;
		if (i2p::http::MergeChunkedResponse (is, os)) body = os.str ();
	}
	if (gz && !body.empty ())
	{
		std::vector<uint8_t> out (16 * 1024);
		i2p::data::GzipInflator inflator;
		(void)inflator.Inflate ((const uint8_t *)body.data (), body.size (), out.data (), out.size ());
	}
	res.body = body.substr (0, 64);
	(void)res.to_string ();
	return 0;
}
