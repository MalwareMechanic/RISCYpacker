#pragma once
#include <string>
#include "Hollower.h"
class Unpacker
{
public:
	Unpacker();
	bool UnpackIntoProcess(std::wstring procPath);
	~Unpacker();
private:
	IMAGE_DOS_HEADER *exe;
	IMAGE_DOS_HEADER *Unpack();
};

