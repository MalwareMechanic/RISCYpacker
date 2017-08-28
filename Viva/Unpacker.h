#pragma once
class Unpacker
{
public:
	Unpacker();
	IMAGE_DOS_HEADER *GetExecutble();
	~Unpacker();
};

