// Fuzzes the IPC object deserializer (Serializable::DeserializeNew) over every class registered
// with the SerializerFactory: core-service requests/responses, MountOptions, HostDevice, VolumeInfo...
#include "Platform/Platform.h"
#include "Platform/MemoryStream.h"
#include "Platform/Serializable.h"
#include <cstdint>

using namespace VeraCrypt;

extern "C" int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
	// MemoryStream's constructor takes &Data[0] of an empty vector (UB); an empty input cannot parse anyway.
	if (size == 0)
		return 0;
	try
	{
		shared_ptr <Stream> in (new MemoryStream (ConstBufferPtr (data, size)));
		shared_ptr <Serializable> object (Serializable::DeserializeNew (in));
		if (object)
		{
			shared_ptr <Stream> out (new MemoryStream);
			object->Serialize (out);
		}
	}
	catch (...) { }
	return 0;
}
