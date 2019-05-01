 
#include "allocation.h"
SOCKET_TYPE socket_type;

allocation::allocation()
{
}
allocation::allocation(int transport_protocol, socket_base* sock)
{
	socket_type = TCP_SOCKET;
}
 
allocation::~allocation()
{
}

 