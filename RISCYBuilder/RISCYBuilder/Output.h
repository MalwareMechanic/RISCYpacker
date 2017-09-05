#pragma once
#include <iostream>
#include <string>

#define ERROR_64BIT_IMAGE 0xF0000001
#define ERROR_INVALID_EXE 0xF0000002
#define ERROR_INVALID_ARGUEMENT 0xF0000003
#define ERROR_CANNOT_OPEN_FILE 0xF0000004
#define SUCCESS 0x00000000

namespace Error {
	static void ErrOut(std::wstring err) { std::wcout << err << std::endl; }
	static void ErrExit(std::wstring err,int code) {
		ErrOut(err); exit(code);
	}
};