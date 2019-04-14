  
#ifndef ALLOCATION_H
#define ALLOCATION_H
#include "commonTypes.h"
 
struct allocation_desc* allocation_list_find_tuple(struct list_head* list,
	int transport_protocol, const  address_type* server_addr,
	const  address_type* client_addr);
 
 
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

/**
 * \brief Find if a peer (network address only) has a permissions installed.
 * \param desc allocation descriptor
 * \param family address family (IPv4 or IPv6)
 * \param peer_addr network address
 * \return pointer on allocation_permission or NULL if not found
 */
struct allocation_permission* allocation_desc_find_permission(struct allocation_desc* desc, int family, const uint8_t* peer_addr);

/**
 * \brief Add a permission for a peer.
 * \param desc allocation descriptor
 * \param lifetime lifetime of the permission
 * \param family address family (IPv4 or IPv6)
 * \param peer_addr network address
 * \return 0 if success, -1 otherwise
 */
int allocation_desc_add_permission(struct allocation_desc* desc,uint32_t lifetime, int family, const uint8_t* peer_addr);

/**
 * \brief Reset the timer of the permission.
 * \param permission allocation permission
 * \param lifetime lifetime
 */
void allocation_permission_set_timer(struct allocation_permission* permission,uint32_t lifetime);

/**
 * Find a TCP relay identified by its peer address and port.
 * \param desc allocation descriptor
 * \param family peer family address (IPv4 or IPv6)
 * \param peer_addr peer address
 * \param peer_port peer port
 * \return TCP relay if found, NULL otherwise
 */
struct allocation_tcp_relay* allocation_desc_find_tcp_relay_addr( struct allocation_desc* desc, int family, const uint8_t* peer_addr,uint16_t peer_port);


/**
 * Find a TCP relay identified by its peer address and port.
 * \param desc allocation descriptor
 * \param family peer family address (IPv4 or IPv6)
 * \param peer_addr peer address
 * \param peer_port peer port
 * \return TCP relay if found, NULL otherwise
 */
struct allocation_tcp_relay* allocation_desc_find_tcp_relay_addr(
	struct allocation_desc* desc, int family, const uint8_t* peer_addr,
	uint16_t peer_port);

/**
 * \brief Add a TCP relay.
 * \param desc allocation descriptor
 * \param id connection ID
 * \param peer_sock peer data connection socket
 * \param family peer address family (IPv4 or IPv6)
 * \param peer_addr peer address
 * \param peer_port peer port
 * \param timeout TCP relay timeout (if no ConnectionBind is received)
 * \param buffer_size internal buffer size (for peer data)
 * \param connect_msg_id Connect request message ID if client contact another
 * peer otherwise put NULL
 * \return 0 if success, -1 otherwise
 */
int allocation_desc_add_tcp_relay(struct allocation_desc* desc, uint32_t id,
	int peer_sock, int family, const uint8_t* peer_addr, uint16_t peer_port,
	uint32_t timeout, size_t buffer_size, uint8_t* connect_msg_id);


/**
 * \brief Find a TCP relay identified by its connection ID.
 * \param desc allocation descriptor
 * \param id connection ID
 * \return TCP relay if found, NULL otherwise
 */
struct allocation_tcp_relay* allocation_desc_find_tcp_relay_id(
	struct allocation_desc* desc, uint32_t id);
/**
 * \brief Set timer of an TCP relay.
 *
 * If timeout is 0, the timer is stopped.
 * \param relay TCP relay
 * \param timeout timeout to set
 */
void allocation_tcp_relay_set_timer(struct allocation_tcp_relay* relay,
	uint32_t timeout);

/**
 * \brief Find a specified token.
 * \param list list of tokens
 * \param id token ID (64 bit)
 * \return pointer on allocation_token or NULL if not found
 */
struct allocation_token* allocation_token_list_find(struct list_head* list,
	uint8_t* id);

/**
 * \brief Set timer of an allocation token.
 * \param token allocation descriptor
 * \param lifetime lifetime timer
 */
void allocation_token_set_timer(struct allocation_token* token,
	uint32_t lifetime);
/**
 * \brief Remove and free a token from a list.
 * \param list list of allocations
 * \param desc allocation to remove
 */
void allocation_token_list_remove(struct list_head* list,
	struct allocation_token* desc);
/**
 * \brief Free a token.
 * \param token pointer on pointer allocated by allocation_token_new
 */
void allocation_token_free(struct allocation_token** token);
/**
 * \brief Set timer of an allocation descriptor.
 * \param desc allocation descriptor
 * \param lifetime lifetime timer
 */
void allocation_desc_set_timer(struct allocation_desc* desc, uint32_t lifetime);

/**
 * \brief Remove and free an allocation from a list.
 * \param list list of allocations
 * \param desc allocation to remove
 */
void allocation_list_remove(struct list_head* list,
	struct allocation_desc* desc);
/**
 * \brief Free an allocation descriptor.
 * \param desc pointer on pointer allocated by allocation_desc_new
 */
void allocation_desc_free(struct allocation_desc** desc);
/**
 * \brief Add an allocation to a list.
 * \param list list of allocations
 * \param desc allocation descriptor to add
 */
void allocation_list_add(struct list_head* list, struct allocation_desc* desc);

/**
 * \brief Create a new allocation descriptor.
 * \param id transaction ID of the Allocate request
 * \param transport_protocol transport protocol (i.e. TCP, UDP, ...)
 * \param username login of the user
 * \param key MD5 hash over username, realm and password
 * \param realm realm of the user
 * \param nonce nonce of the user
 * \param relayed_addr relayed address and port
 * \param server_addr server network address and port
 * \param client_addr client network address and port
 * \param addr_size sizeof address
 * \param lifetime expire of the allocation
 * \return pointer on struct allocation_desc, or NULL if problem
 */
allocation_desc * allocation_desc_new(const uint8_t * id, uint8_t transport_protocol, const char * username, const unsigned char * key, const char * realm, const unsigned char * nonce, const sockaddr_storage * relayed_addr, const address_type * server_addr, const address_type * client_addr, uint32_t lifetime);


/**
 * \brief Create a new token.
 * \param id token ID (MUST be 64 bit length)
 * \param sock opened socket
 * \param lifetime lifetime
 * \return pointer on allocation_token or NULL if problem
 */
struct allocation_token* allocation_token_new(uint8_t* id, int sock,
	uint32_t lifetime);
/**
 * \brief Add a token to a list.
 * \param list list of tokens
 * \param token token to add
 */
void allocation_token_list_add(struct list_head* list,
	struct allocation_token* token);

/**
 * \brief Remove a TCP relay.
 * \param list list of TCP relays
 * \param relay relay to remove
 */
void allocation_tcp_relay_list_remove(struct list_head* list,
	struct allocation_tcp_relay* relay);

#endif