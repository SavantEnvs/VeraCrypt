// Fuzzes the hash functions (incremental vs one-shot digest must agree) and the PBKDF2/HMAC key
// derivation built on them, with a tiny iteration count.
#include "Platform/Platform.h"
#include "Volume/Hash.h"
#include "Volume/Pkcs5Kdf.h"
#include "Volume/VolumePassword.h"
#include "Crypto/cpu.h"
#include <cstdint>
#include <cstdlib>
#include <cstring>

using namespace VeraCrypt;

extern "C" int LLVMFuzzerInitialize (int *, char ***)
{
#ifdef CRYPTOPP_CPUID_AVAILABLE
	DetectX86Features ();
#endif
	return 0;
}

extern "C" int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
	if (size < 4)
		return 0;

	HashList hashes = Hash::GetAvailableAlgorithms();
	HashList::iterator h = hashes.begin();
	std::advance (h, data[0] % hashes.size());
	// Hash cores (e.g. Whirlpool) load 64-bit words straight from the caller's buffer, so keep every
	// ProcessData call 8-byte aligned.
	size_t chunk = 8 * (1 + data[1] % 32);
	size_t keySize = 1 + data[2];
	int iterations = 1 + data[3] % 3;
	size_t bodySize = size - 4;
	alignas (64) static uint8 aligned[1 << 16];
	if (bodySize > sizeof (aligned))
		bodySize = sizeof (aligned);
	memcpy (aligned, data + 4, bodySize);
	const uint8 *body = aligned;

	try
	{
		shared_ptr <Hash> whole = (*h)->GetNew();
		shared_ptr <Hash> parts = (*h)->GetNew();
		SecureBuffer d1 (whole->GetDigestSize()), d2 (parts->GetDigestSize());

		whole->Init();
		whole->ProcessData (ConstBufferPtr (body, bodySize));
		whole->GetDigest (d1);

		parts->Init();
		for (size_t off = 0; off < bodySize; off += chunk)
			parts->ProcessData (ConstBufferPtr (body + off, bodySize - off < chunk ? bodySize - off : chunk));
		parts->GetDigest (d2);
		if (memcmp (d1.Ptr(), d2.Ptr(), d1.Size()) != 0)
			abort();

		shared_ptr <Pkcs5Kdf> kdf = Pkcs5Kdf::GetAlgorithm (**h);
		size_t pwSize = bodySize < 64 ? bodySize : 64;
		VolumePassword password (body, pwSize);
		size_t saltSize = bodySize - pwSize < 64 ? bodySize - pwSize : 64;
		SecureBuffer salt (saltSize ? saltSize : 1);
		if (saltSize)
			memcpy (salt.Ptr(), body + pwSize, saltSize);
		SecureBuffer key (keySize);
		kdf->DeriveKey (key, password, salt, iterations);
	}
	catch (...) { }
	return 0;
}
