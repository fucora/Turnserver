#pragma once
#ifndef COMMONTYPES_H
#define COMMONTYPES_H

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
#include <time.h>
#include <sys/time.h>
#include <malloc.h>
#include <stdint.h>
#include <sys/types.h>
//////////// 
#include "myDeletegate.h"
#include "dbg.h"
#include "list.h"
///////////////////
#include "ns_turn_msg_defs.h"
#include "ns_turn_defs.h"
/////////////
#include <openssl/rand.h>
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
#include <boost/serialization/utility.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/export.hpp> 
#include <boost/serialization/serialization.hpp>
#include <boost/serialization/access.hpp> 
#include <boost/serialization/map.hpp>

#include <boost/archive/binary_oarchive.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/serialization/binary_object.hpp>

 


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
	uint8_t* client_addr; /**< Client address */
	unsigned short client_port; 
	uint8_t* server_addr; /**< Server address */
	unsigned short server_port;
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
	socket_base* client_sock; /**< Client data connection (client <-> server) */
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
	socket_base* tuple_sock; /**< Socket for the connection between the TURN server and the
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
 * \enum account_state
 * \brief Account access state.
 */
enum account_state
{
	AUTHORIZED, /**< Client is authorized to access service */
	RESTRICTED, /**< Client has limited access to service (bandwidth, ...) */
	REFUSED, /**< Client is always refused to access service (i.e. blacklist) */
};

/**
 * \struct denied_address
 * \brief Describes an address.
 */
struct denied_address
{
	int family; /**< AF family (AF_INET or AF_INET6) */
	uint8_t addr[16]; /**< IPv4 or IPv6 address */
	uint8_t mask; /**< Network mask of the address */
	uint16_t port; /**< Port */
	struct list_head list; /**< For list management */
};

/**
 * \struct account_desc
 * \brief Account descriptor.
 */
struct account_desc
{
	char username[514]; /**< Username */
	char realm[256]; /**< Realm */
	unsigned char key[64]; /**< MD5 hash */
	enum account_state state; /**< Access state */
	size_t allocations; /**< Number of allocations used */
	int is_tmp; /**< If account is a temporary account */
	struct list_head list; /**< For list management */
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
void uint32_convert(const unsigned char* data, size_t data_len, uint32_t* t);
void uint64_convert(const unsigned char* data, size_t data_len, uint64_t* t);
/**
 * \brief Print a digest.
 * \param buf buffer
 * \param len length of buffer
 */
void digest_print(const unsigned char* buf, size_t len);
/**
 * \brief Find a account with specified username and realm from a list.
 * \param list list of accounts
 * \param username
 * \param realm realm
 * \return pointer on account_desc or NULL if not found
 */
struct account_desc* account_list_find(struct list_head* list, const char* username, const char* realm);


/**
 * \brief Generate random bytes.
 * \param id buffer that will be filled with random value
 * \param len length of id
 * \return 0 if successfull, -1 if the random number is cryptographically weak
 */
int random_bytes_generate(uint8_t* id, size_t len);


/**
 * \brief Remove and free an account from a list.
 * \param list list of accounts
 * \param desc account to remove
 */
void account_list_remove(struct list_head* list, struct account_desc* desc);


/**
 * \struct socket_desc
 * \brief Descriptor for TCP client connected.
 *
 * It contains a buffer for TCP segment reconstruction.
 */
struct socket_desc
{
	socket_base* sock; /**< Socket descriptor */
	char buf[1500]; /**< Internal buffer for TCP stream reconstruction */
	size_t buf_pos; /**< Position in the internal buffer */
	size_t msg_len; /**< Message length that is not complete */
	int tls; /**< If socket uses TLS */
	struct list_head list; /**< For list management */
};


/**
 * \def SIGRT_EXPIRE_CHANNEL
 * \brief Signal value when channel expires.
 */
#define SIGRT_EXPIRE_CHANNEL (SIGRTMIN + 2) 
 /**
  * \def SIGRT_EXPIRE_PERMISSION
  * \brief Signal value when a permission expires.
  */
#define SIGRT_EXPIRE_PERMISSION (SIGRTMIN + 1)

  /**
   * \def SIGRT_EXPIRE_ALLOCATION
   * \brief Signal value when an allocation expires.
   */
#define SIGRT_EXPIRE_ALLOCATION (SIGRTMIN)

   /**
	* \def SIGRT_EXPIRE_TOKEN
	* \brief Signal value when token expires.
	*/
#define SIGRT_EXPIRE_TOKEN (SIGRTMIN + 3)

	/**
	 * \def SIGRT_EXPIRE_TCP_RELAY
	 * \brief Signal value when TCP relay expires (no ConnectionBind received).
	 */
#define SIGRT_EXPIRE_TCP_RELAY (SIGRTMIN + 4)

#endif