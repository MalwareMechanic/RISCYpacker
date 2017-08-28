#pragma once
#include <string>
#include <vector>
#include <map>

struct SectionInfo {
	SectionInfo(char name[], int ro, int vo, int rs, int vs) { memcpy(sectionName,name,strlen((char*)name)); _rOffset = ro; _vOffset = vo; _rSize = rs; _vSize = vs; }
	char sectionName[8] = { };
	int _rOffset, _vOffset, _rSize, _vSize;
};

struct IAT {
	unsigned int offset;
	std::map<std::wstring, std::vector<std::wstring>> functions;
};


class PEData
{
public:
	PEData(IMAGE_DOS_HEADER* exe);
	IAT GetIAT() { return iat; }
	std::vector<SectionInfo> GetSections() { return si; }
	~PEData();
private:
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
