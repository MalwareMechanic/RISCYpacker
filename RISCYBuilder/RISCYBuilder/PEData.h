#pragma once
#include <string>
#include <Windows.h>
#include <vector>
#include <map>

struct SectionInfo {
	SectionInfo(char name[], int ro, int vo, int rs, int vs) { memcpy(sectionName, name, strlen((char*)name)); _rOffset = ro; _vOffset = vo; _rSize = rs; _vSize = vs; }
	char sectionName[8] = {};
	int _rOffset, _vOffset, _rSize, _vSize;
};

struct Thunk {
	std::string libname;
	std::vector<std::string> functionNames;
};

struct IAT {
	unsigned int offset;
	std::vector<Thunk> thunks;
};


class PEData
{
public:
	PEData(IMAGE_DOS_HEADER* exe);
	PEData(std::wstring filePath);
	void Init(IMAGE_DOS_HEADER* exe);
	void WriteResource(BYTE* buff);
	IAT GetIAT() { return iat; }
	std::vector<SectionInfo> GetSections() { return si; }
	IMAGE_OPTIONAL_HEADER *GetOptionalHeader() { return this->I_optionalHeader; }
	void *GetModuleBase() { return exe; }
	DWORD PEData::GetEntryPoint() { return this->I_optionalHeader->AddressOfEntryPoint; }
	~PEData();
protected:
	IMAGE_OPTIONAL_HEADER *I_optionalHeader;
	IMAGE_NT_HEADERS *I_ntHeader;
	IMAGE_FILE_HEADER *I_fileHeader;
	IMAGE_DATA_DIRECTORY *I_dataDirectory;
	DWORD Rva2Offset(DWORD dwRva);
	void ExtractSections();
	void ExtractImports();
	std::vector<SectionInfo> si;
	IAT iat;
	void* exe;
};
