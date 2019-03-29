#pragma once
#include "commonTypes.h"
#include "turn.h"

class StunProtocol
{
#pragma region –≠“È
public:
	   bool IsChannelData();
	   uint16_t getRequestType();
	   uint16_t getRequestLength();
	   uint16_t getRequestMethod(); 
	   bool IsErrorRequest();


#pragma endregion

public:
	StunProtocol(buffer_type data, int length); 
	~StunProtocol();

private:
	int getAttr(const char * bufferPtr, uint16_t attrtype);

};

