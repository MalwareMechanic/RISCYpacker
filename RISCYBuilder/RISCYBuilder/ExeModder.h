#pragma once
#include <Windows.h>
#include <string>
#include "PEData.h"

class ExeModder : public PEData
{
public:
	ExeModder(IMAGE_DOS_HEADER* exe) : PEData(exe) {

	}
	void WriteToResource(BYTE* data);
	~ExeModder();
private:
	IMAGE_DOS_HEADER *exe;
	std::string packerPath;
};

