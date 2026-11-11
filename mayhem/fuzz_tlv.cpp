// Fuzzes the smart-card TLV (BER-style) parser.
#include "Platform/Platform.h"
#include "Common/TLVParser.h"
#include <cstdint>

using namespace VeraCrypt;

static size_t Walk (const shared_ptr <TLVNode> &node, int depth)
{
	if (!node || depth > 64)
		return 0;
	size_t count = 1 + node->Value->size();
	for (const shared_ptr <TLVNode> &sub : *node->Subs)
		count += Walk (sub, depth + 1);
	return count;
}

extern "C" int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
	if (size < 2)
		return 0;
	uint16 tag = (uint16) ((data[0] << 8) | data[1]);
	try
	{
		shared_ptr <TLVNode> root = TLVParser::TLV_Parse (data + 2, size - 2);
		Walk (root, 0);
		TLVParser::TLV_Find (root, tag);
	}
	catch (TLVException &) { }
	catch (...) { }
	return 0;
}
