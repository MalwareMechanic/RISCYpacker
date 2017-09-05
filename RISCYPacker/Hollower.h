#pragma once
#include "PEData.h"
#include <string>
#include <vector>
#include "PEData.h"
#include "StringCryptor.h"

#define SECTION_BASE_PLACEHOLDER 0xdeadbeef
#define IAT_LOCATION_PLACEHOLDER 0xbeefdead
#define CONTAINS_STRING_PLACEHOLDER 0xfeeddead
#define KERNEL32_PLACEHOLDER 0xdeadc0de
#define LOADLIBRARY_PLACEHOLDER 0xc0dedead
#define GETPROCADDRESS_PLACEHOLDER 0xc0deface
#define OEP_PLACEHOLDER 0xc0defade
#define PUSH 0x68
#define PUSH_PLACEHOLDER 0xfec0de00

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
typedef LONG NTSTATUS;

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef NTSTATUS(WINAPI *TNtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);

typedef NTSTATUS(WINAPI *TNtMapViewOfSection)(
	HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID *BaseAddress,
	ULONG_PTR ZeroBits,
	SIZE_T CommitSize,
	PLARGE_INTEGER SectionOffset,
	PSIZE_T ViewSize,
	DWORD InheritDisposition,
	ULONG AllocationType,
	ULONG Win32Protect);

typedef NTSTATUS(WINAPI *TNtCreateSection)(
	PHANDLE SectionHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PLARGE_INTEGER MaximumSize,
	ULONG SectionPageProtection,
	ULONG AllocationAttributes,
	HANDLE FileHandle
	);

class Hollower
{
public:
	Hollower(std::wstring targetProcPath, IMAGE_DOS_HEADER *unpackedExe);
	HANDLE DoHollow();
	~Hollower();
private:
	PEData *packedPEData,*hollowedPEData;
	void *imageOffset;
	void* localSectionBase = NULL;
	void* remoteBase = NULL;
	void WriteIATInfo(size_t IATInfoOffset);
	void FixRelocations();
	size_t containsStringSize=0;
	size_t IATshellcodeSize=0;
	std::wstring hollowedProcPath;
	HANDLE hProc;
	TNtUnmapViewOfSection NtUnmapViewOfSection;
	TNtMapViewOfSection NtMapViewOfSection;
	TNtCreateSection NtCreateSection;
	std::vector<PEData *> sections;
	
	/*************HOLLOW ROUTINES***************/
	void ReMapExe();
	size_t SerializeIATInfo();
	void InjectBootstrapCode(size_t offset);
	void CreateSuspendedProcess();

};




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


