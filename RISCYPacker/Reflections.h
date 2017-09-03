#pragma once
#include "stdafx.h"
#include <map>
#define RET_INT3_INT3_INT3 0xCCCCCCC3

size_t GetFunctionSize(void* function)
{
	size_t size=0;
	while (*(DWORD*)(&((BYTE*)function)[size - 4]) != RET_INT3_INT3_INT3)
		size++;
	return size;
}

template <typename T>
void FindReplaceMemory(void* mem, size_t memLength, std::map<T,T> replacer)
{
	void* pos;
	for (std::map<T, T>::iterator it = replacer.begin(); it != replacer.end(); ++it)
	{
		pos = mem;
		while ((int)pos<((int)mem + (int)memLength))
		{
			if (*(T*)pos == it->first) {
				*(T*)pos = (T)it->second;
				break;
			}
		  pos=((BYTE*)pos)+1;
		}
	}
	
}