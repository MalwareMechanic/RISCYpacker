#pragma once
#include "PEData.h"
#include <string>
#include <vector>
#include "PEData.h"

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
	PEData *peData;
	void* loadedExeSection=NULL;
	void* remoteBase=NULL;
	std::wstring path;
	HANDLE hProc;
	TNtUnmapViewOfSection NtUnmapViewOfSection;
	TNtMapViewOfSection NtMapViewOfSection;
	TNtCreateSection NtCreateSection;
	std::vector<PEData *> sections;
	//Applies memory remapping with unpacked sections
	void ReMapExe();
	void RebuildIAT();
	//Extract unpacked PE data to assist in mapping and IAT rebuilding
	void ExtractPEData(IMAGE_DOS_HEADER *exe);
	void CreateSuspendedProcess();

};
