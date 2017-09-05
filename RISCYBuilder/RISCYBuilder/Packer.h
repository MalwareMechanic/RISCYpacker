#pragma once
#include <Windows.h>
#include <vector>
#include "Output.h"

class Packer
{
public:
	Packer();
	BYTE* Pack(IMAGE_DOS_HEADER *exe,size_t fSize);
	~Packer();
private:
	std::vector<char> packedBinary;
	std::vector<char> ZLIBcompress(IMAGE_DOS_HEADER *exe, size_t fSize);
	void Crypt();

};

