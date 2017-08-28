#include "stdafx.h"
#include "PEData.h"


PEData::PEData(IMAGE_DOS_HEADER *exe)
{
	this->exe = (void*)exe;
	this->I_ntHeader = (IMAGE_NT_HEADERS*)((int)exe + ((IMAGE_DOS_HEADER*)exe)->e_lfanew);
	this->I_fileHeader = (IMAGE_FILE_HEADER*)&I_ntHeader->FileHeader;
	this->I_optionalHeader = (IMAGE_OPTIONAL_HEADER*)&this->I_ntHeader->OptionalHeader;

	ExtractSections();
	ExtractImports();

}

DWORD PEData::Rva2Offset(DWORD dwRva)
{
	IMAGE_SECTION_HEADER *secHeader = IMAGE_FIRST_SECTION(this->I_ntHeader);

	for (USHORT i = 0; i < this->I_fileHeader->NumberOfSections; i++)
	{
		if (dwRva >= secHeader->VirtualAddress)
		{
			if (dwRva < secHeader->VirtualAddress + secHeader->Misc.VirtualSize)
				return (DWORD)(dwRva - secHeader->VirtualAddress + secHeader->PointerToRawData);
		}
		secHeader++;
	}
	return -1;
}

void PEData::ExtractSections()
{
	IMAGE_SECTION_HEADER *secHeader = IMAGE_FIRST_SECTION(this->I_ntHeader);

	for (int i = 0; i < this->I_fileHeader->NumberOfSections; i++)
	{
		si.push_back(SectionInfo((char*)secHeader->Name, secHeader->PointerToRawData, secHeader->VirtualAddress, secHeader->SizeOfRawData, secHeader->Misc.VirtualSize));
		secHeader++;
	}

}

void PEData::ExtractImports()
{

	IMAGE_IMPORT_DESCRIPTOR *imports = (IMAGE_IMPORT_DESCRIPTOR*)((DWORD)exe+Rva2Offset(this->I_optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));
	IMAGE_THUNK_DATA *thunk = (IMAGE_THUNK_DATA*) ((int)exe + imports->OriginalFirstThunk);

	thunk->u1.AddressOfData;
}

PEData::~PEData()
{
}
