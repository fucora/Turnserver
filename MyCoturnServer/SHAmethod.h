#pragma once
#ifndef SHAMETHOD_H
#define SHAMETHOD_H

#include "commonTypes.h"
#include "turn.h"
 


class SHAmethod
{
	 
public:
	SHAmethod();
	SHAmethod(turn_attr_message_integrity * message_integrity);
	size_t get_hmackey_size();
	~SHAmethod();
};
#endif

