#pragma once
#include <cstdio>  
#include <stdint.h>
#include <iostream>
#include <memory>
#include <array>
#include <netinet/in.h>
#include <list>
#include <functional> 
#include <string>
#include <algorithm>
//////////// 
#include "myDeletegate.h"
#include "dbg.h"
#include "list.h"
////////
#include <boost/shared_ptr.hpp>
#include <boost/asio.hpp>
#include <boost/asio/placeholders.hpp>
#include <boost/system/error_code.hpp>
#include <boost/bind/bind.hpp> 
#include <boost/enable_shared_from_this.hpp>
#include <boost/signals2.hpp>  
#include <boost/utility/result_of.hpp>
#include <boost/typeof/typeof.hpp>
#include <boost/assign.hpp>
#include <boost/ref.hpp>
#include <boost/function.hpp>  
#include <boost/asio/basic_socket.hpp>

using namespace boost::asio;
using namespace std;



typedef  char buffer_type[4096];

typedef ip::tcp::socket tcp_socket;
typedef ip::udp::socket udp_socket;
typedef ip::address address_type;



#define	MAX(a, b) ((a) > (b) ? (a) : (b))

/**
 * \def MIN
 * \brief Minimum number of the two arguments.
 */
#define	MIN(a, b) ((a) < (b) ? (a) : (b))

struct allocation_token
{
	uint8_t id[8]; /**< Token ID */
	int sock; /**< The opened socket */
	timer_t expire_timer; /**< Expire timer */
	struct list_head list; /**< For list management */
	struct list_head list2; /**< For list management (expired list) */
};

/**
 * \struct allocation_tuple
 * \brief Allocation tuple.
 */
struct allocation_tuple
{
	int transport_protocol; /**< Transport protocol */
	address_type client_addr; /**< Client address */
	address_type server_addr; /**< Server address */
};

/**
 * \struct allocation_permission
 * \brief Network address permission.
 */
struct allocation_permission
{
	int family; /**< Address family */
	uint8_t peer_addr[16]; /**< Peer address */
	timer_t expire_timer; /**< Expire timer */
	struct list_head list; /**< For list management */
	struct list_head list2; /**< For list management (expired list) */
};

/**
 * \struct allocation_channel
 * \brief Allocation channel.
 */
struct allocation_channel
{
	int family; /**< Address family */
	uint8_t peer_addr[16]; /**< Peer address */
	uint16_t peer_port; /**< Peer port */
	uint16_t channel_number; /**< Channel bound to this peer */
	timer_t expire_timer; /**< Expire timer */
	struct list_head list; /**< For list management */
	struct list_head list2; /**< For list management (expired list) */
};

/**
 * \struct allocation_tcp_relay
 * \brief TCP relay information.
 */
struct allocation_tcp_relay
{
	uint32_t connection_id; /**< Connection ID */
	int family; /**< TCP relay family (IPv4 or IPv6) */
	uint8_t peer_addr[16]; /**< Peer address */
	uint16_t peer_port; /**< Peer port */
	int peer_sock; /**< Peer data connection (server <-> peer) */
	int client_sock; /**< Client data connection (client <-> server) */
	timer_t expire_timer; /**< Expire timer */
	int newConnection; /** int new  < If the connection is newly initiated */
	int ready; /**< If remote peer is connected (i.e. connect() has succeed
				 before timeout) */
	time_t created; /**< Time when this relay has been created (this is used to
					  calculted timeout) */
	char* buf; /**< Internal buffer for peer data (before receiving
				 ConnectionBind) */
	size_t buf_len; /**< Length of current data in internal buffer */
	size_t buf_size; /**< Capacity of internal buffer */
	uint8_t connect_msg_id[12]; /**< TURN message ID of the connection request
								  (if any) */
	struct list_head list; /**< For list management */
	struct list_head list2; /**< For list management (expired list) */
};

/**
 * \struct allocation_desc
 * \brief Allocation descriptor.
 */
struct allocation_desc
{
	char* username; /**< Username of client */
	unsigned char key[16]; /**< MD5 hash over username, realm and password */
	char realm[256]; /**< Realm of user */
	unsigned char nonce[48]; /**< Nonce of user */
	int relayed_transport_protocol; /**< Relayed transport protocol used */
	struct sockaddr_storage relayed_addr; /**< Relayed transport address */
	struct allocation_tuple tuple; /**< 5-tuple */
	struct list_head peers_channels; /**< List of channel to peer bindings */
	struct list_head peers_permissions; /**< List of peers permissions */
	struct list_head tcp_relays; /**< TCP relays information */
	int relayed_sock; /**< Socket for the allocated transport address */
	int relayed_sock_tcp; /**< Socket for the allocated transport address to
							contact TCP peer (RFC6062). It is set to -1 if Connect
							request succeed */
	int relayed_tls; /**< If allocation has been set in TLS */
	int relayed_dtls; /**< If allocation has been set in DTLS */
	int tuple_sock; /**< Socket for the connection between the TURN server and the
					  TURN client */
	uint8_t transaction_id[12]; /**< Transaction ID of the Allocate Request */
	timer_t expire_timer; /**< Expire timer */
	unsigned long bucket_capacity; /**< Capacity of token bucket */
	unsigned long bucket_tokenup; /**< Number of tokens available for upload */
	unsigned long bucket_tokendown; /**< Number of tokens available for
									  download */
	struct timeval last_timeup; /**< Last time of bandwidth limit checking for
								   upload */
	struct timeval last_timedown; /**< Last time of bandwidth limit checking for
									 download */
	struct list_head list; /**< For list management */
	struct list_head list2; /**< For list management (expired list) */
};





