
#ifndef ALLOCATION_H
#define ALLOCATION_H

#include "commonTypes.h"

class allocation
{
public:
	allocation();
	allocation(SOCKET_TYPE socket_type, socket_base * sock);
	~allocation();

public:bool is_valid = false;
public:stun_tid tid;
};

#endif // ALLOCATION