#include "stdafx.h"
#include "Packer.h"
#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/filter/zlib.hpp>
#include <wincrypt.h>

#define KEY_SIZE 32

Packer::Packer()
{
}


Packer::~Packer()
{
}

void Packer::Crypt()
{

	BYTE key[KEY_SIZE];
	HCRYPTPROV hProv;
	CryptAcquireContext(&hProv, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
	CryptGenRandom(hProv, KEY_SIZE, key);
	int i = 0;
	for (std::vector<char>::iterator it = this->packedBinary.begin(); it != this->packedBinary.end(); ++it)
	{
		*it = *it^key[i%KEY_SIZE];
		i++;
	}

	return;
}

std::vector<char> Packer::ZLIBcompress(IMAGE_DOS_HEADER *exe, size_t fSize)
{
	boost::iostreams::filtering_ostream os;
	const char* end = (char*)((int)exe + fSize);
	const char *cExe = (char*)exe;

	std::vector<char> decompressed;
	decompressed.insert(decompressed.end(), cExe, end);
	std::vector<char> compressed = std::vector<char>();

	{
		boost::iostreams::filtering_ostream os;

		os.push(boost::iostreams::zlib_compressor());
		os.push(std::back_inserter(compressed));

		boost::iostreams::write(os, reinterpret_cast<const char*>(&decompressed[0]), decompressed.size());
	}


	return compressed;
}

BYTE* Packer::Pack(IMAGE_DOS_HEADER *exe,size_t fSize)
{
	
	this->packedBinary = ZLIBcompress(exe, fSize);
	Crypt();
	return (BYTE*)this->packedBinary.data();
}
