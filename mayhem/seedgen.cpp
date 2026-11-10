// One-off generator for the committed starter seeds (not part of build.sh / the images).
//   make -f mayhem/lib.mk OUT=/tmp/o LIB_CXXFLAGS="-O1" && \
//   clang++ -std=c++20 -Ilibi2pd mayhem/seedgen.cpp /tmp/o/libi2pd.a -lboost_program_options -lssl -lcrypto -lz -lpthread -latomic -o /tmp/seedgen && /tmp/seedgen mayhem
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>
#include <sys/stat.h>
#include "Crypto.h"
#include "Identity.h"
#include "RouterInfo.h"
#include "Base.h"
#include "util.h"
#include "Timestamp.h"

using namespace i2p::data;

static void put (const std::string& path, const std::vector<uint8_t>& d)
{
	std::ofstream f (path, std::ios::binary);
	f.write ((const char *)d.data (), d.size ());
}
static void put (const std::string& path, const std::string& s)
{
	put (path, std::vector<uint8_t> (s.begin (), s.end ()));
}
static void be (std::vector<uint8_t>& v, uint64_t x, int n) { for (int i = n - 1; i >= 0; i--) v.push_back ((x >> (8*i)) & 0xff); }
static void app (std::vector<uint8_t>& v, const uint8_t * p, size_t n) { v.insert (v.end (), p, p + n); }

int main (int argc, char ** argv)
{
	std::string root = argc > 1 ? argv[1] : "mayhem";
	i2p::crypto::InitCrypto (false);
	for (auto d : {"fuzz_http_req", "fuzz_http_res", "fuzz_http_url", "fuzz_routerinfo", "fuzz_identity", "fuzz_leaseset", "fuzz_base"})
		mkdir ((root + "/" + d).c_str (), 0755), mkdir ((root + "/" + d + "/testsuite").c_str (), 0755);
	auto T = [&](const char * t) { return root + "/" + t + "/testsuite/"; };

	// identities
	struct { const char * name; uint16_t sig, crypto; } ids[] = {
		{"ed25519_x25519", SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519, CRYPTO_KEY_TYPE_ECIES_X25519_AEAD},
		{"ed25519_elgamal", SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519, CRYPTO_KEY_TYPE_ELGAMAL},
		{"dsa_elgamal", SIGNING_KEY_TYPE_DSA_SHA1, CRYPTO_KEY_TYPE_ELGAMAL},
		{"p256_elgamal", SIGNING_KEY_TYPE_ECDSA_SHA256_P256, CRYPTO_KEY_TYPE_ELGAMAL},
		{"p384_elgamal", SIGNING_KEY_TYPE_ECDSA_SHA384_P384, CRYPTO_KEY_TYPE_ELGAMAL},
		{"p521_elgamal", SIGNING_KEY_TYPE_ECDSA_SHA512_P521, CRYPTO_KEY_TYPE_ELGAMAL},
		{"reddsa_x25519", SIGNING_KEY_TYPE_REDDSA_SHA512_ED25519, CRYPTO_KEY_TYPE_ECIES_X25519_AEAD},
		{"gost256", SIGNING_KEY_TYPE_GOSTR3410_CRYPTO_PRO_A_GOSTR3411_256, CRYPTO_KEY_TYPE_ELGAMAL},
	};
	PrivateKeys edKeys;
	for (auto& id : ids)
	{
		auto keys = PrivateKeys::CreateRandomKeys (id.sig, id.crypto);
		uint8_t buf[1024];
		size_t l = keys.GetPublic ()->ToBuffer (buf, sizeof buf);
		put (T ("fuzz_identity") + id.name, std::vector<uint8_t> (buf, buf + l));
		if (id.sig == SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519 && id.crypto == CRYPTO_KEY_TYPE_ECIES_X25519_AEAD) edKeys = keys;
	}
	// fixed router signing identity for fuzz_routerinfo
	{
		uint8_t buf[1024];
		size_t l = edKeys.ToBuffer (buf, sizeof buf);
		FILE * f = fopen ((root + "/ri_keys.h").c_str (), "w");
		fprintf (f, "// fixed Ed25519/X25519 router keys (PrivateKeys::ToBuffer) used to re-sign fuzzed RouterInfo bodies\nstatic const unsigned char kRouterKeys[] = {");
		for (size_t i = 0; i < l; i++) fprintf (f, "%s0x%02x,", i % 16 ? "" : "\n\t", buf[i]);
		fprintf (f, "\n};\n");
		fclose (f);
	}

	// router infos: bodies (selector 0) and full buffers (selector 1)
	uint8_t sk[32], iv[16], ik[32];
	for (int i = 0; i < 32; i++) sk[i] = i * 7 + 1, ik[i] = i * 5 + 3;
	for (int i = 0; i < 16; i++) iv[i] = i + 9;
	sk[31] &= 0x7f; // RouterInfo only accepts static keys with the top bit clear (x25519 public key)
	auto idLen = edKeys.GetPublic ()->GetFullLen ();
	auto sigLen = edKeys.GetPublic ()->GetSignatureLen ();
	for (int variant = 0; variant < 5; variant++)
	{
		i2p::data::LocalRouterInfo ri;
		ri.SetRouterIdentity (edKeys.GetPublic ());
		ri.SetProperty ("netId", "2"); ri.SetProperty ("router.version", "0.9.66"); // RouterInfo is unreachable without both
		switch (variant)
		{
			case 0: ri.AddNTCP2Address (sk, iv, boost::asio::ip::make_address ("93.184.216.34"), 12345);
				ri.SetProperty ("caps", "LR"); break;
			case 1: ri.AddNTCP2Address (sk, iv, boost::asio::ip::make_address ("93.184.216.34"), 12345);
				ri.AddSSU2Address (sk, ik, boost::asio::ip::make_address ("93.184.216.34"), 12345);
				ri.SetProperty ("caps", "XfR"); break;
			case 2: ri.AddNTCP2Address (sk, iv, boost::asio::ip::make_address ("2606:2800:220:1::1"), 4567);
				ri.AddSSU2Address (sk, ik, boost::asio::ip::make_address ("2606:2800:220:1::1"), 4567);
				ri.SetProperty ("caps", "PfR6"); break;
			case 3: ri.AddNTCP2Address (sk, iv, 9000, 0x01 | 0x02);
				ri.AddSSU2Address (sk, ik, 9000, 0x01 | 0x02);
				ri.SetProperty ("caps", "LU"); break;
			case 4: ri.AddNTCP2Address (sk, iv, boost::asio::ip::make_address ("93.184.216.77"), 22222);
				ri.SetProperty ("caps", "OfR"); ri.SetProperty ("family", "example"); break;
		}
		ri.CreateBuffer (edKeys);
		std::vector<uint8_t> full (ri.GetBuffer (), ri.GetBuffer () + ri.GetBufferLen ());
		std::vector<uint8_t> body (full.begin () + idLen, full.end () - sigLen);
		body.insert (body.begin (), 0x00);
		full.insert (full.begin (), 0x01);
		put (T ("fuzz_routerinfo") + "body" + std::to_string (variant), body);
		put (T ("fuzz_routerinfo") + "full" + std::to_string (variant), full);
	}

	// leasesets: the harness adds the identity (edKeys) and the signature, and for LeaseSet2 the published time
	for (int variant = 0; variant < 3; variant++)
	{
		uint8_t gw[32], encKey[32];
		memset (gw, 0x40 + variant, sizeof gw); memset (encKey, 0x11 * (variant + 1), sizeof encKey);
		std::vector<uint8_t> ls (1, 1); // selector byte 1 = LeaseSet2
		be (ls, 600, 2); be (ls, variant == 2 ? 0x0002 : 0, 2); // expires, flags
		be (ls, 0, 2); // properties
		ls.push_back (1); be (ls, 4, 2); be (ls, 32, 2); app (ls, encKey, 32); // key sections
		ls.push_back (variant + 1); // leases; end dates can't be valid in a static seed (now - 51s .. now + 12min)
		for (int i = 0; i <= variant; i++) { app (ls, gw, 32); be (ls, 1000 + i, 4); be (ls, 0, 4); }
		put (T ("fuzz_leaseset") + "ls2_" + std::to_string (variant), ls);
	}
	{
		std::vector<uint8_t> ls (1, 0); // selector byte 0 = legacy LeaseSet
		std::vector<uint8_t> enc (256, 0x22), sgn (edKeys.GetPublic ()->GetSigningPublicKeyLen (), 0x33);
		app (ls, enc.data (), 256); app (ls, sgn.data (), sgn.size ());
		ls.push_back (2);
		for (int i = 0; i < 2; i++) { std::vector<uint8_t> gw (32, 0x50 + i); app (ls, gw.data (), 32); be (ls, 77 + i, 4); be (ls, 0x0000100000000000ULL, 8); }
		put (T ("fuzz_leaseset") + "ls1", ls);
	}

	// http
	put (T ("fuzz_http_req") + "get", "GET /index.html HTTP/1.1\r\nHost: example.i2p\r\nUser-Agent: MYOB/6.66 (AN/ON)\r\nAccept: text/html\r\nConnection: close\r\n\r\n");
	put (T ("fuzz_http_req") + "connect", "CONNECT stats.i2p:443 HTTP/1.1\r\nHost: stats.i2p:443\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n");
	put (T ("fuzz_http_req") + "post", "POST /submit?a=1&b=2 HTTP/1.0\r\nHost: foo.b32.i2p\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 7\r\nReferer: http://foo.i2p/\r\n\r\nx=1&y=2");
	put (T ("fuzz_http_req") + "abs", "GET http://user:pw@host.i2p:8080/a%20b/c?q=1#frag HTTP/1.1\r\nHost: host.i2p:8080\r\nX-Forwarded-For: 1.2.3.4\r\n\r\n");
	put (T ("fuzz_http_res") + "ok", "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\nServer: i2pd\r\n\r\nHello, world!");
	put (T ("fuzz_http_res") + "chunked", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n5\r\nhello\r\n0\r\n\r\n");
	put (T ("fuzz_http_res") + "redirect", "HTTP/1.0 302 Found\r\nLocation: http://example.i2p/new\r\nContent-Length: 0\r\nSet-Cookie: a=b; Path=/\r\n\r\n");
	put (T ("fuzz_http_res") + "notmod", "HTTP/1.1 304 Not Modified\r\nETag: \"abc\"\r\nContent-Encoding: x-i2p-gzip\r\n\r\n");
	put (T ("fuzz_http_url") + "full", "https://user:pass@site.i2p:7070/path/to?name=value&n2=v%202#frag");
	put (T ("fuzz_http_url") + "ipv6", "http://[2001:db8::1]:8080/index.html?x=1");
	put (T ("fuzz_http_url") + "rel", "/just/a/path?q=%41%42%00%zz");
	put (T ("fuzz_http_url") + "chunk", "4\r\nWiki\r\n5\r\npedia\r\nE\r\n in\r\n\r\nchunks.\r\n0\r\n\r\n");

	// base: selector byte then payload
	auto sel = [](uint8_t s, const std::string& p) { std::vector<uint8_t> v (1, s); v.insert (v.end (), p.begin (), p.end ()); return v; };
	put (T ("fuzz_base") + "b64", sel (0, "dGVzdA=="));
	put (T ("fuzz_base") + "b64i2p", sel (0, "AAECAwQFBgcICQoLDA0ODw~~-A=="));
	put (T ("fuzz_base") + "b32", sel (1, "orsxg5a"));
	put (T ("fuzz_base") + "roundtrip", sel (2, "The quick brown fox jumps over the lazy dog"));
	{
		std::vector<uint8_t> m (1, 3);
		const char * kv[][2] = {{"caps", "XfR"}, {"netId", "2"}, {"router.version", "0.9.66"}};
		std::vector<uint8_t> body;
		for (auto& p : kv) { body.push_back (strlen (p[0])); app (body, (const uint8_t *)p[0], strlen (p[0])); body.push_back ('='); body.push_back (strlen (p[1])); app (body, (const uint8_t *)p[1], strlen (p[1])); body.push_back (';'); }
		be (m, body.size (), 2); app (m, body.data (), body.size ());
		put (T ("fuzz_base") + "mapping", m);
	}
	{
		// gzip stream of "hello hello hello hello\n"
		const uint8_t gz[] = {0x1f,0x8b,0x08,0x00,0,0,0,0,0x00,0x03,0xcb,0x48,0xcd,0xc9,0xc9,0x57,0xc8,0x40,0x27,0xb8,0x00,0x6a,0x5c,0x39,0xfb,0x18,0x00,0x00,0x00};
		std::vector<uint8_t> g (1, 4); app (g, gz, sizeof gz);
		put (T ("fuzz_base") + "gzip", g);
	}
	return 0;
}
