// Fuzzes the smart-card ResponseAPDU container (setBytes/appendData/getBytes round trip).
#include "Platform/Platform.h"
#include "Common/ResponseAPDU.h"
#include <cstdint>
#include <cstdlib>

using namespace VeraCrypt;

extern "C" int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
	if (size < 3)
		return 0;
	uint16 sw = (uint16) ((data[0] << 8) | data[1]);
	vector <uint8> payload (data + 3, data + size);
	try
	{
		ResponseAPDU a (payload, sw);
		ResponseAPDU b;
		b.setBytes (a.getBytes());
		if (b.getSW() != a.getSW() || b.getData() != a.getData())
			abort();

		ResponseAPDU c;
		c.setBytes (payload);
		c.getNr(); c.getSW1(); c.getSW2();
		if (data[2] & 1)
			c.appendData (payload);
		else
			c.appendData (payload.data(), payload.size());
		c.setSW (sw);
		ResponseAPDU d (c);
		d = a;
		d.clear();
	}
	catch (...) { }
	return 0;
}
