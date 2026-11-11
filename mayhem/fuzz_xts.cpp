// Fuzzes the XTS sector encryption of every cipher/cascade with fuzzer-chosen keys, sector numbers
// and data, and checks that decryption inverts encryption.
#include "Platform/Platform.h"
#include "Volume/EncryptionAlgorithm.h"
#include "Volume/EncryptionMode.h"
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
	const size_t sectorSize = 512;
	if (size < 1 + 4)
		return 0;

	EncryptionAlgorithmList algorithms = VeraCrypt::EncryptionAlgorithm::GetAvailableAlgorithms();
	EncryptionAlgorithmList::iterator a = algorithms.begin();
	std::advance (a, data[0] % algorithms.size());
	shared_ptr <VeraCrypt::EncryptionAlgorithm> ea = (*a)->GetNew();

	shared_ptr <EncryptionMode> mode;
	foreach (shared_ptr <EncryptionMode> candidate, EncryptionMode::GetAvailableModes())
	{
		if (ea->IsModeSupported (candidate) && candidate->GetName() == L"XTS")
		{
			mode = candidate->GetNew();
			break;
		}
	}
	if (!mode)
		return 0;

	uint32 sectorIndex;
	memcpy (&sectorIndex, data + 1, 4);
	data += 5; size -= 5;

	size_t keySize = ea->GetKeySize();
	if (size < 2 * keySize + sectorSize)
		return 0;

	// The ciphers load 32/64-bit words straight from the key pointer; the application always passes
	// SecureBuffers, so hand them aligned copies too.
	alignas (64) uint8 key[512];
	alignas (64) uint8 plain[8 * 512];
	alignas (64) uint8 work[8 * 512];
	if (2 * keySize > sizeof (key))
		return 0;
	memcpy (key, data, 2 * keySize);
	size_t sectors = (size - 2 * keySize) / sectorSize;
	if (sectors > 8)
		sectors = 8;
	memcpy (plain, data + 2 * keySize, sectors * sectorSize);
	memcpy (work, plain, sectors * sectorSize);

	try
	{
		ea->SetKey (ConstBufferPtr (key, keySize));
		mode->SetKey (ConstBufferPtr (key + keySize, keySize));
		ea->SetMode (mode);

		ea->EncryptSectors (work, sectorIndex, sectors, sectorSize);
		ea->DecryptSectors (work, sectorIndex, sectors, sectorSize);
		if (memcmp (work, plain, sectors * sectorSize) != 0)
			abort();
	}
	catch (...) { }
	return 0;
}
