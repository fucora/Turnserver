  
#include "commonTypes.h"




struct allocation_desc* allocation_list_find_tuple(struct list_head* list,
	int transport_protocol, const  address_type server_addr,
	const  address_type client_addr, socklen_t addr_size);
 
struct allocation_channel* allocation_desc_find_channel_number(
	struct allocation_desc* desc, uint16_t channel);

