// RISCYBuilder.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include <string>
#include "Packer.h"

int main()
{
	int argc;
	LPWSTR *argv;
	argv = CommandLineToArgvW(GetCommandLineW(), &argc);
	if (argc < 2)
		Error::ErrExit(L"Not Enough Arguments",ERROR_INVALID_ARGUEMENT);
	

	HANDLE hExe = CreateFile(argv[1], GENERIC_READ, 0, NULL, OPEN_EXISTING, NULL, NULL);
	if (!hExe)
		Error::ErrExit(L"File either does not exist or cannot be open", ERROR_CANNOT_OPEN_FILE);
	LARGE_INTEGER fSize = { 0,0 };
	GetFileSizeEx(hExe, &fSize);
	IMAGE_DOS_HEADER* exe = (IMAGE_DOS_HEADER*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fSize.LowPart);
	ReadFile(hExe, (void*)exe, fSize.LowPart, NULL, NULL);
	Packer p;
	BYTE* packedExe = p.Pack(exe,fSize.LowPart);

    return SUCCESS;
}

