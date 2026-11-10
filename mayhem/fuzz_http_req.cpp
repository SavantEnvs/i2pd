#include <cstdint>
#include <cstddef>
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
	if (size > 64 * 1024) return -1;
	std::string_view in ((const char *)data, size);
	i2p::http::HTTPReq req;
	int r = req.parse (in);
	if (r <= 0) return -1;
	(void)req.GetHeader ("Host");
	(void)req.GetNumHeaders ("Accept");
	(void)req.GetNumHeaders ();
	std::string s = req.to_string ();
	i2p::http::HTTPReq req2;
	(void)req2.parse (s);
	req.UpdateHeader ("Host", "example.i2p");
	req.RemoveHeader ("Proxy-");
	req.RemoveHeader ("X-", "X-Keep");
	req.AddHeader ("Connection", "close");
	(void)req.to_string ();
	i2p::http::URL url;
	if (url.parse (req.uri)) (void)url.to_string (true);
	return 0;
}
