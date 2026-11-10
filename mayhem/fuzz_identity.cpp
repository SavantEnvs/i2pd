#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include "Crypto.h"
#include "Identity.h"
#include "quiet.h"

extern "C" int LLVMFuzzerInitialize (int *, char ***)
{
	QuietLogs ();
	i2p::crypto::InitCrypto (false);
	return 0;
}

extern "C" int LLVMFuzzerTestOneInput (const uint8_t * data, size_t size)
{
	if (size > 4096) return -1;
	using namespace i2p::data;
	IdentityEx ident;
	size_t l = ident.FromBuffer (data, size);
	if (!l)
	{
		IdentityEx b64;
		(void)b64.FromBase64 (std::string_view ((const char *)data, size));
		return -1;
	}
	uint8_t out[4096];
	(void)ident.ToBuffer (out, sizeof out);
	(void)ident.ToBase64 ();
	(void)ident.GetIdentHash ().ToBase32 ();
	size_t sigLen = ident.GetSignatureLen ();
	if (sigLen && l + sigLen <= size)
		(void)ident.Verify (data, l, data + l);
	(void)ident.GetSigningKeyType ();
	(void)ident.GetCryptoKeyType ();
	(void)ident.IsRSA ();
	Identity id;
	id.FromBuffer (data, size);
	PrivateKeys keys;
	if (keys.FromBuffer (data, size))
	{
		uint8_t sig[1024];
		if (keys.GetSignatureLen () <= sizeof sig) keys.Sign (data, 16, sig);
	}
	return 0;
}
