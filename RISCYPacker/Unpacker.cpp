#include "stdafx.h"
#include "Unpacker.h"
#include "resource.h"

Unpacker::Unpacker()
{
}

IMAGE_DOS_HEADER *Unpacker::GetExecutble()
{
	HMODULE hMod = GetModuleHandle(NULL);
	HRSRC res = FindResource(hMod, MAKEINTRESOURCE(IDR_DATA1), L"DATA");

    return (IMAGE_DOS_HEADER*)LoadResource(hMod, res);
}

Unpacker::~Unpacker()
{
}
