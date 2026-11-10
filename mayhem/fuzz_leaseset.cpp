#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>
#include "Crypto.h"
#include "I2PEndian.h"
#include "Identity.h"
#include "LeaseSet.h"
#include "Timestamp.h"
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

// Both LeaseSet kinds verify a signature over the whole buffer, so a mutated input would never get past it.
// byte 0 & 3: 0 = legacy LeaseSet, 1 = LeaseSet2: the rest of the input is the body, wrapped in a fixed
//   identity (LeaseSet2 also gets the current time as its published timestamp, which it rejects once it is
//   older than 12 minutes) and signed with the matching fixed key;
// 2 = the rest is a whole legacy LeaseSet, 3 = a whole LeaseSet2 (bit 2 of byte 0 selects the encrypted
//   variant); the signature check will normally reject these.
// LeaseSet2 reads buf[-1] (it lives inside a DatabaseStore message), so buf[0] below is that spare byte.
extern "C" int LLVMFuzzerTestOneInput (const uint8_t * data, size_t size)
{
	if (size < 2) return -1;
	uint8_t sel = data[0] & 3;
	const uint8_t * body = data + 1;
	size_t bodyLen = size - 1;
	std::vector<uint8_t> buf (1);
	uint8_t storeType = i2p::data::NETDB_STORE_TYPE_STANDARD_LEASESET2;
	if (sel < 2)
	{
		uint8_t idbuf[512];
		size_t idLen = keys->GetPublic ()->ToBuffer (idbuf, sizeof idbuf);
		buf.insert (buf.end (), idbuf, idbuf + idLen);
		if (sel == 1)
		{
			uint8_t ts[4];
			htobe32buf (ts, i2p::util::GetSecondsSinceEpoch ());
			buf.insert (buf.end (), ts, ts + 4);
		}
		buf.insert (buf.end (), body, body + bodyLen);
		size_t signedLen = buf.size () - 1;
		size_t sigLen = keys->GetPublic ()->GetSignatureLen ();
		buf.resize (buf.size () + sigLen);
		if (sel == 1) buf[0] = storeType, keys->Sign (buf.data (), signedLen + 1, buf.data () + 1 + signedLen);
		else keys->Sign (buf.data () + 1, signedLen, buf.data () + 1 + signedLen);
	}
	else
	{
		buf.insert (buf.end (), body, body + bodyLen);
		if (sel == 3 && (data[0] & 4)) storeType = i2p::data::NETDB_STORE_TYPE_ENCRYPTED_LEASESET2;
	}
	size_t len = buf.size () - 1;
	if (len > i2p::data::MAX_LS_BUFFER_SIZE) return -1;
	const uint8_t * p = buf.data () + 1;

	if (sel == 0 || sel == 2)
	{
		i2p::data::LeaseSet ls (p, len);
		if (!ls.IsValid ()) return -1;
		(void)ls.GetNonExpiredLeases (false);
		(void)ls.GetNonExpiredLeases (true);
		(void)ls.GetExpirationTime ();
		(void)ls.GetIdentHash ();
		i2p::data::LeaseSet ls2 (p, len, false);
		return 0;
	}
	i2p::data::LeaseSet2 ls (storeType, p, len);
	if (!ls.IsValid ()) return -1;
	(void)ls.GetNonExpiredLeases (false);
	(void)ls.GetPublishedTimestamp ();
	(void)ls.IsPublic ();
	(void)ls.IsNewer (p, len);
	return 0;
}
