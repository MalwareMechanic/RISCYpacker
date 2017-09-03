#pragma once
#include "stdafx.h"

/**********************************<No CRT/Windows API allowed>**************************************/

bool ContainsString(char* src, char* str, bool isUnicode)
{
	int i = 0, k = 0, strLen = 0;
	//strlen
	while ((str[strLen] != NULL && !isUnicode) || ((str[strLen - 1] != NULL || str[strLen] != NULL) && isUnicode))
		strLen++;
	strLen = strLen / (isUnicode + 1);
	isUnicode ? strLen += strLen % 2 : 0;

	//string contains?
	while ((src[i] && !isUnicode) || ((src[i - 1] | src[i]) && isUnicode))
	{
		while (src[i] == str[k])
		{
			if (k == strLen)
				return true;
			i += (1 + isUnicode);
			k += (1 + isUnicode);
		}
		i += (1 + isUnicode);
		k = 0;
	}
	return false;
}

void IATshellcode()
{
	_PEB *PEB;
	__asm {
		pushad
		push edi;
		push fs : [0x30];
		pop edi;
		mov PEB, edi;
		pop edi;
	}

	/*place holders applied to search and replace these addresses at runtime*/
	DWORD *serializedIATinfo = (DWORD*)SECTION_BASE_PLACEHOLDER;
	DWORD *iatLocation = (DWORD*)IAT_LOCATION_PLACEHOLDER;
	DWORD(*TContainsString)(char* src, char* str, bool isUnicode) = (DWORD(*)(char*, char*, bool))CONTAINS_STRING_PLACEHOLDER;
	char* kernel32Str = (char*)KERNEL32_PLACEHOLDER;
	char* loadlibraryStr = (char*)LOADLIBRARY_PLACEHOLDER;
	char* getprocaddressStr = (char*)GETPROCADDRESS_PLACEHOLDER;
	DWORD oep = OEP_PLACEHOLDER;
	/**********************************************************************/

	LIST_ENTRY *leHead = &PEB->Ldr->InMemoryOrderModuleList;
	LIST_ENTRY *leNode = leHead;
	PLDR_DATA_TABLE_ENTRY dataEntry;
	void* kernel32Base = NULL;
	while (leNode->Flink != leHead) {
		leNode = leNode->Flink;
		dataEntry = (PLDR_DATA_TABLE_ENTRY)CONTAINING_RECORD(leNode, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		if (TContainsString((char*)dataEntry->FullDllName.Buffer, kernel32Str, true))
		{
			kernel32Base = dataEntry->DllBase;
			break;
		}
	}

	if (kernel32Base == NULL)
		return;

	IMAGE_DOS_HEADER* kernel32Image = (IMAGE_DOS_HEADER*)kernel32Base;
	IMAGE_NT_HEADERS *kernel32NtHeader = (IMAGE_NT_HEADERS*)((int)kernel32Image + (kernel32Image)->e_lfanew);
	IMAGE_OPTIONAL_HEADER *kernel32OptionalHeader = (IMAGE_OPTIONAL_HEADER*)&kernel32NtHeader->OptionalHeader;

	IMAGE_EXPORT_DIRECTORY *kernel32Exports = (IMAGE_EXPORT_DIRECTORY*)((int)kernel32Base + kernel32OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	DWORD *functionsNames = (DWORD*)((int)kernel32Base + kernel32Exports->AddressOfNames);
	int funcIndex = 0, getProcAddderIndex, loadLibraryIndex;
	while (1)
	{

		if (TContainsString((char*)((int)kernel32Base + *functionsNames), getprocaddressStr, false))
		{
			getProcAddderIndex = funcIndex + 2;
		}
		if (TContainsString((char*)((int)kernel32Base + *functionsNames), loadlibraryStr, false))
		{
			loadLibraryIndex = funcIndex + 1;
			break;
		}
		functionsNames++;

		funcIndex++;
	}

	DWORD *functions = (DWORD*)((int)kernel32Base + kernel32Exports->AddressOfFunctions);
	DWORD(*TGetProcAddress)(DWORD base, char* funcName) = ((DWORD(*)(DWORD, char*))((int)kernel32Base + functions[getProcAddderIndex]));
	DWORD(*TLoadLibrary)(char* libName) = ((DWORD(*)(char*))((int)kernel32Base + functions[loadLibraryIndex]));

	int i = 0;
	char* currLib = (char*)serializedIATinfo;
	char* currFunc;
	DWORD libBase;
	//start -1 for loops sake
	iatLocation--;
	//while not end of IAT info (null.null.null)
	while (((char*)serializedIATinfo)[i] != NULL || ((char*)serializedIATinfo)[i + 1] != NULL || ((char*)serializedIATinfo)[i + 2] != NULL)
	{
		//Library end (null.null)
		if (((char*)serializedIATinfo)[i] == NULL && ((char*)serializedIATinfo)[i + 1] == NULL)
		{
			i += 2;
			currLib = (char*)(((char*)serializedIATinfo) + i);
			
			//eat up library string
			while (((char*)serializedIATinfo)[i] != NULL)
			{
				i++;
			}
			i++;
			libBase = TLoadLibrary(currLib);

			*iatLocation = 0x00000000;
			iatLocation++;
		}
		currFunc = (char*)(((char*)serializedIATinfo) + i);
		//eat up function string
		while (((char*)serializedIATinfo)[i] != NULL)
		{
			i++;
		}
		i++;

		*iatLocation = (DWORD)TGetProcAddress(libBase, currFunc);
		iatLocation++;
	}

	__asm {
		popad
		jmp oep;
	}
}

/**********************************</No CRT/Windows API allowed>**************************************/

