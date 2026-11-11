// Fuzzes the decrypted volume-header parser (VolumeHeader::Deserialize) and then keys the selected
// encryption algorithm with the key area it found. The header CRCs are recomputed so the parser
// gets past its integrity checks.
#include "Platform/Platform.h"
#include "Volume/EncryptionAlgorithm.h"
#include "Volume/EncryptionMode.h"
#include "Volume/Crc32.h"
#include "Volume/VolumeHeader.h"
#include "Crypto/cpu.h"
#include <cstdint>
#include <cstring>

using namespace VeraCrypt;

namespace
{
	const size_t HeaderSize = 512;
	const size_t DecryptedSize = HeaderSize - 64;
	const size_t KeyAreaOffset = 192;
	const size_t KeyAreaCrcOffset = 8;
	const size_t HeaderCrcOffset = 188;

	class ParsableHeader : public VolumeHeader
	{
	public:
		ParsableHeader () : VolumeHeader (HeaderSize) { }

		bool Parse (const ConstBufferPtr &header, shared_ptr <VeraCrypt::EncryptionAlgorithm> &ea, shared_ptr <EncryptionMode> &mode)
		{
			return Deserialize (header, ea, mode);
		}
	};

	void PutBigEndian32 (uint8 *p, uint32 v)
	{
		p[0] = uint8 (v >> 24); p[1] = uint8 (v >> 16); p[2] = uint8 (v >> 8); p[3] = uint8 (v);
	}
}

extern "C" int LLVMFuzzerInitialize (int *, char ***)
{
#ifdef CRYPTOPP_CPUID_AVAILABLE
	DetectX86Features ();
#endif
	return 0;
}

extern "C" int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
	if (size < 2)
		return 0;

	EncryptionAlgorithmList algorithms = VeraCrypt::EncryptionAlgorithm::GetAvailableAlgorithms();
	EncryptionModeList modes = EncryptionMode::GetAvailableModes();

	EncryptionAlgorithmList::iterator a = algorithms.begin();
	std::advance (a, data[0] % algorithms.size());
	EncryptionModeList::iterator m = modes.begin();
	std::advance (m, data[1] % modes.size());
	shared_ptr <VeraCrypt::EncryptionAlgorithm> ea = *a;
	shared_ptr <EncryptionMode> mode = *m;

	alignas (64) uint8 header[DecryptedSize];
	memset (header, 0, sizeof (header));
	size_t n = size - 2 < sizeof (header) ? size - 2 : sizeof (header);
	memcpy (header, data + 2, n);

	memcpy (header, "VERA", 4);
	PutBigEndian32 (header + KeyAreaCrcOffset, Crc32::ProcessBuffer (ConstBufferPtr (header + KeyAreaOffset, 256)));
	PutBigEndian32 (header + HeaderCrcOffset, Crc32::ProcessBuffer (ConstBufferPtr (header, HeaderCrcOffset)));

	try
	{
		ParsableHeader parsed;
		if (parsed.Parse (ConstBufferPtr (header, sizeof (header)), ea, mode))
		{
			alignas (64) uint8 sector[512];
			memset (sector, 0xA5, sizeof (sector));
			ea->EncryptSectors (sector, 1, 1, sizeof (sector));
			ea->DecryptSectors (sector, 1, 1, sizeof (sector));
		}
	}
	catch (...) { }
	return 0;
}
