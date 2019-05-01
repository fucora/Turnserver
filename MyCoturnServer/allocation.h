
#ifndef ALLOCATION_H
#define ALLOCATION_H

#include "commonTypes.h"
 
class allocation
{ 
public:
	allocation();
	allocation(int transport_protocol, socket_base * sock);
	~allocation();
};

#endif // ALLOCATION