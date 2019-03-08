#include "turn_agreement.h"



turn_agreement::turn_agreement()
{
}


turn_agreement::~turn_agreement()
{
}


int  turn_agreement::stun_get_method_str(buffer_type buf, int len)
{
	if (!buf || len < 2) return (uint16_t)-1;

	uint16_t tt = ntohs(((const uint16_t*)buf)[0]);
	return (tt & 0x000F) | ((tt & 0x00E0) >> 1) |
		((tt & 0x0E00) >> 2) | ((tt & 0x3000) >> 2);
}
