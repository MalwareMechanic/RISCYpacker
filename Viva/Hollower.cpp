#include "stdafx.h"
#include "Hollower.h"


Hollower::Hollower(std::wstring targetProcPath, IMAGE_DOS_HEADER *unpackedExe)
{
	this->path = targetProcPath;
	PEData *pd = new PEData(unpackedExe);

	HMODULE hmNtdll = GetModuleHandle(L"ntdll");

	this->NtUnmapViewOfSection = (TNtUnmapViewOfSection) GetProcAddress(hmNtdll, "NtUnmapViewOfSection");
	this->NtMapViewOfSection = (TNtMapViewOfSection)GetProcAddress(hmNtdll, "NtMapViewOfSection");
	this->NtCreateSection = (TNtCreateSection)GetProcAddress(hmNtdll, "NtCreateSection");
}

void Hollower::ReMapExe()
{

}

void Hollower::ExtractPEData(IMAGE_DOS_HEADER* exe)
{

}

HANDLE Hollower::DoHollow()
{
	//Create Suspended process, sets hProc member with HANDLE result
	CreateSuspendedProcess();

	ReMapExe();

	return this->hProc;
}

void Hollower::CreateSuspendedProcess()
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	memset(&si, 0, sizeof(si));

	si.cb = sizeof(STARTUPINFO);

	CreateProcess(path.c_str(), NULL, NULL, NULL, false, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

	this->hProc = pi.hProcess;
}

Hollower::~Hollower()
{

}

