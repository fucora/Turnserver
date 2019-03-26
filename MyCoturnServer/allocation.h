  
#include "commonTypes.h"




struct allocation_desc* allocation_list_find_tuple(struct list_head* list,
	int transport_protocol, const  address_type server_addr,
	const  address_type client_addr, socklen_t addr_size);
 
struct allocation_channel* allocation_desc_find_channel_number(struct allocation_desc* desc, uint16_t channel);

/**
 * \brief Find if a channel number has a peer (transport address).
 * \param desc allocation descriptor
 * \param channel channel number
 * \return pointer on allocation_channel if found, NULL otherwise
 */
struct allocation_channel* allocation_desc_find_channel_number(struct allocation_desc* desc, uint16_t channel);

/**
 * \brief Find if a peer (transport address) has a channel bound.
 * \param desc allocation descriptor
 * \param family address family (IPv4 or IPv6)
 * \param peer_addr network address
 * \param peer_port peer port
 * \return the channel if the peer has already a channel bound, 0 otherwise
 */
uint32_t allocation_desc_find_channel(struct allocation_desc* desc, int family, const uint8_t* peer_addr, uint16_t peer_port);

/**
 * \brief Reset the timer of the channel.
 * \param channel allocation channel
 * \param lifetime lifetime
 */
void allocation_channel_set_timer(struct allocation_channel* channel,uint32_t lifetime);


/**
 * \brief Add a channel to a peer (transport address).
 * \param desc allocation descriptor
 * \param channel channel number
 * \param lifetime lifetime of the channel
 * \param family address family (IPv4 or IPv6)
 * \param peer_addr network address
 * \param peer_port peer port
 * \return 0 if success, -1 otherwise
 */
int allocation_desc_add_channel(struct allocation_desc* desc, uint16_t channel, uint32_t lifetime, int family, const uint8_t* peer_addr,uint16_t peer_port);




