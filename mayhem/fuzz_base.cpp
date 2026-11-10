#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>
#include "Crypto.h"
#include "Base.h"
#include "Gzip.h"
#include "util.h"
#include "quiet.h"

extern "C" int LLVMFuzzerInitialize (int *, char ***)
{
	QuietLogs ();
	return 0;
}

// byte 0 selects the codec: base64, base32, encode/decode round trip, Mapping, gzip.
extern "C" int LLVMFuzzerTestOneInput (const uint8_t * data, size_t size)
{
	if (size < 1 || size > 16 * 1024) return -1;
	uint8_t sel = data[0] % 5;
	const uint8_t * p = data + 1;
	size_t len = size - 1;
	std::string_view sv ((const char *)p, len);
	std::vector<uint8_t> out (len + 64);
	switch (sel)
	{
		case 0:
			(void)i2p::data::Base64ToByteStream (sv, out.data (), out.size ());
			break;
		case 1:
			(void)i2p::data::Base32ToByteStream (sv, out.data (), out.size ());
			break;
		case 2:
		{
			auto b64 = i2p::data::ByteStreamToBase64 (p, len);
			std::vector<uint8_t> back (len + 4);
			size_t n = i2p::data::Base64ToByteStream (b64, back.data (), back.size ());
			if (n != len || (len && memcmp (back.data (), p, len))) __builtin_trap ();
			if (!len) break; // ByteStreamToBase32 reads inBuf[0] unconditionally
			auto b32 = i2p::data::ByteStreamToBase32 (p, len);
			n = i2p::data::Base32ToByteStream (b32, back.data (), back.size ());
			if (n != len || memcmp (back.data (), p, len)) __builtin_trap ();
			break;
		}
		case 3:
		{
			i2p::util::Mapping m;
			size_t n = m.FromBuffer (p, len);
			if (n)
			{
				(void)m["caps"];
				(void)m.Contains ("netId");
				uint8_t b[4096];
				(void)m.ToBuffer (b, sizeof b);
			}
			i2p::util::Mapping m2;
			if (len >= 2) (void)m2.FromBuffer (len - 2, p + 2, len - 2);
			break;
		}
		default:
		{
			i2p::data::GzipInflator inflator;
			(void)inflator.Inflate (p, len, out.data (), out.size ());
			break;
		}
	}
	return 0;
}
