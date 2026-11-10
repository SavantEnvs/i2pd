#include <cstdint>
#include <cstddef>
#include <cstring>
#include <memory>
#include <vector>
#include "Crypto.h"
#include "Identity.h"
#include "RouterInfo.h"
#include "ri_keys.h"
#include "quiet.h"

static i2p::data::PrivateKeys * keys;

extern "C" int LLVMFuzzerInitialize (int *, char ***)
{
	QuietLogs ();
	i2p::crypto::InitCrypto (false);
	keys = new i2p::data::PrivateKeys;
	keys->FromBuffer (kRouterKeys, sizeof kRouterKeys);
	return 0;
}

// byte 0: 0 = fuzzed body (published .. properties) wrapped in the fixed router identity and re-signed,
// 1 = whole RouterInfo as given (signature check will normally reject it).
extern "C" int LLVMFuzzerTestOneInput (const uint8_t * data, size_t size)
{
	if (size < 2 || size > i2p::data::MAX_RI_BUFFER_SIZE) return -1;
	std::vector<uint8_t> ri;
	if (data[0] & 1)
		ri.assign (data + 1, data + size);
	else
	{
		uint8_t idbuf[512];
		size_t idLen = keys->GetPublic ()->ToBuffer (idbuf, sizeof idbuf);
		size_t sigLen = keys->GetPublic ()->GetSignatureLen ();
		ri.assign (idbuf, idbuf + idLen);
		ri.insert (ri.end (), data + 1, data + size);
		size_t signedLen = ri.size ();
		ri.resize (signedLen + sigLen);
		keys->Sign (ri.data (), signedLen, ri.data () + signedLen);
	}
	if (ri.size () > i2p::data::MAX_RI_BUFFER_SIZE) return -1;
	i2p::data::RouterInfo info (ri.data (), ri.size ());
	if (info.IsUnreachable () && !info.HasValidAddresses ()) return -1;
	(void)info.GetCaps ();
	(void)info.GetVersion ();
	(void)info.IsFloodfill ();
	(void)info.IsEligibleFloodfill ();
	(void)info.IsHighCongestion (true);
	(void)info.IsPublished (true);
	(void)info.IsPublished (false);
	(void)info.IsSSU2PeerTesting (true);
	(void)info.IsSSU2Introducer (false);
	(void)info.GetNTCP2V4Address ();
	(void)info.GetNTCP2V6Address ();
	(void)info.GetSSU2V4Address ();
	(void)info.GetSSU2V6Address ();
	(void)info.GetPublishedNTCP2V4Address ();
	(void)info.GetYggdrasilAddress ();
	(void)info.IsNAT2NATOnly (info);
	(void)info.IsSameSubnet (info);
	(void)info.IsNewer (ri.data (), ri.size ());
	return 0;
}
