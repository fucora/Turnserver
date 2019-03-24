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

#include <stdint.h>
#include <sys/types.h>
//////////// 
#include "myDeletegate.h"
#include "dbg.h"
#include "list.h"
/////////////
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
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
 
typedef char buffer_type[4096];

typedef ip::tcp::endpoint tcp_endpoint;
typedef ip::udp::endpoint udp_endpoint;

typedef ip::tcp::socket tcp_socket;
typedef ip::udp::socket udp_socket;
typedef ip::address address_type;

 
#ifndef MAX
#define	MAX(a, b) ((a) > (b) ? (a) : (b))
#endif // !MAX

 
#ifndef MIN
#define	MIN(a, b) ((a) < (b) ? (a) : (b))
#endif // !1



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


#ifndef XOR_PEER_ADDRESS_MAX
/**
 * \def XOR_PEER_ADDRESS_MAX
 * \brief Maximum number of XOR-PEER-ADDRESS attributes in a request.
 */
#define XOR_PEER_ADDRESS_MAX 5
#endif

struct turn_message
{
	struct turn_msg_hdr* msg; /**< STUN/TURN header */
	struct turn_attr_mapped_address* mapped_addr; /**< MAPPED-ADDRESS attribute */
	struct turn_attr_xor_mapped_address* xor_mapped_addr; /**< XOR-MAPPED-ADDRESS attribute */
	struct turn_attr_alternate_server* alternate_server; /**< ALTERNATE-SERVER attribute */
	struct turn_attr_nonce* nonce; /**< NONCE attribute */
	struct turn_attr_realm* realm; /**< REALM attribute */
	struct turn_attr_username* username; /**< USERNAME attribute */
	struct turn_attr_error_code* error_code; /**< ERROR-CODE attribute */
	struct turn_attr_unknown_attribute* unknown_attribute; /**< UNKNOWN-ATTRIBUTE attribute */
	struct turn_attr_message_integrity* message_integrity; /**< MESSAGE-INTEGRITY attribute */
	struct turn_attr_fingerprint* fingerprint; /**< FINGERPRINT attribute */
	struct turn_attr_software* software; /**< SOFTWARE attribute */
	struct turn_attr_channel_number* channel_number; /**< CHANNEL-NUMBER attribute */
	struct turn_attr_lifetime* lifetime; /**< LIFETIME attribute */
	struct turn_attr_xor_peer_address* peer_addr[XOR_PEER_ADDRESS_MAX]; /**< XOR-PEER-ADDRESS attribute */
	struct turn_attr_data* data; /**< DATA attribute */
	struct turn_attr_xor_relayed_address* relayed_addr; /**< XOR-RELAYED-ADDRESS attribute */
	struct turn_attr_even_port* even_port; /**< REQUESTED-PROPS attribute */
	struct turn_attr_requested_transport* requested_transport; /**< REQUESTED-TRANSPORT attribute */
	struct turn_attr_dont_fragment* dont_fragment; /**< DONT-FRAGMENT attribute */
	struct turn_attr_reservation_token* reservation_token; /**< RESERVATION-TOKEN attribute */
	struct turn_attr_requested_address_family* requested_addr_family; /**< REQUESTED-ADDRESS-FAMILY attribute (RFC6156) */
	struct turn_attr_connection_id* connection_id; /**< CONNECTION-ID attribute (RFC6062) */
	size_t xor_peer_addr_overflow; /**< If set to 1, not all the XOR-PEER-ADDRESS given in request are in this structure */
};
 

/**
 * \enum protocol_type
 * \brief Transport protocol.
 */
enum protocol_type
{
	UDP = IPPROTO_UDP, /**< UDP protocol */
	TCP = IPPROTO_TCP, /**< TCP protocol */
};
/**
 * \struct tls_peer
 * \brief Describes a (D)TLS peer.
 */
struct tls_peer
{
	enum protocol_type type; /**< Transport protocol used (TCP or UDP) */
	int sock; /**< Server socket descriptor */
	SSL_CTX* ctx_client; /**< SSL context for client side */
	SSL_CTX* ctx_server; /**< SSL context for server side */
	struct list_head remote_peers; /**< Remote peers */
	BIO* bio_fake; /**< Fake BIO for read operations */
	int(*verify_callback)(int, X509_STORE_CTX *); /**< Verification callback */
};


uint32_t crc32_generate(const uint8_t* data, size_t len, uint32_t prev);


void hex_convert(const unsigned char* bin, size_t bin_len, unsigned char* hex, size_t hex_len);

void iovec_free_data(struct iovec* iov, uint32_t nb);

int is_little_endian(void);

