#pragma once


#include "commonTypes.h"   
#include "allocation.h"  
#include "turn.h"
#include "socketListener.h"
#include "protocol.h"
#include "StunProtocol.h"

class turn_server
{
public:
	turn_server();
	~turn_server();
	int StartServer();

	void onTcpConnect(tcp_socket * tcpsocket);

	void onTcpMessage(buffer_type * buf, int lenth, tcp_socket * tcpsocket);

	void onUdpMessage(buffer_type * buf, int lenth, udp_socket * udpsocket);

	int MessageHandle2(buffer_type data, int lenth, int transport_protocol, address_type * remoteaddr, address_type * localaddr, int remoteAddrSize, socket_base * sock);

	int MessageHandle(buffer_type data, int lenth, int transport_protocol, address_type * remoteaddr, address_type * localaddr, int remoteAddrSize, socket_base * sock);

	  
	int turnserver_process_turn(int transport_protocol, socket_base * sock, const turn_message * message, const address_type * saddr, const address_type * daddr, socklen_t saddr_size, account_desc * account);

	int turnserver_process_channeldata(int transport_protocol, uint16_t channel_number, const char * buf, ssize_t buflen, address_type * remoteaddr, address_type * localaddr, int remoteAddrSize, list_head * allocation_list);

	int turnserver_check_bandwidth_limit(allocation_desc * desc, size_t byteup, size_t bytedown);

	socklen_t sockaddr_get_size(sockaddr_storage * ss);
	 
	int turnserver_process_channelbind_request(int transport_protocol, socket_base * sock, const turn_message * message, const address_type * saddr, socklen_t saddr_size, allocation_desc * desc);

	int turnserver_process_send_indication(const turn_message * message, allocation_desc * desc);

	int turnserver_is_ipv6_tunneled_address(const uint8_t * addr, size_t addrlen);
 
	int turnserver_process_connect_request(int transport_protocol, socket_base * sock, const turn_message * message, const address_type * saddr, socklen_t saddr_size, allocation_desc * desc);

	int turnserver_process_binding_request(int transport_protocol, socket_base * sock, const turn_message * message, const address_type * saddr, socklen_t saddr_size);

	  
	int turnserver_process_allocate_request(int transport_protocol, socket_base * sock, const turn_message * message, const address_type * saddr, const address_type * daddr, socklen_t saddr_size, account_desc * account);

	int turnserver_process_createpermission_request(int transport_protocol, socket_base * sock, const turn_message * message, const address_type * saddr, socklen_t saddr_size, allocation_desc * desc);
	 
	int turnserver_process_refresh_request(int transport_protocol, socket_base * sock, const turn_message * message, const address_type * saddr, socklen_t saddr_size, allocation_desc * desc, account_desc * account);

	int socket_create(protocol_type type, const char * addr, uint16_t port, int reuse, int nodelay);
	 
	void turnserver_block_realtime_signal(void);

	void turnserver_unblock_realtime_signal(void);

 
	int turn_send_message(int transport_protocol, socket_base * sock, const address_type * remoteaddr, int remoteAddrSize, size_t total_len, const iovec * iov, size_t iovlen);

	int turn_udp_send(socket_base * sock,const address_type * remoteaddr, int remoteAddrSize, const iovec * iov, size_t iovlen);
	 

	int turn_tcp_send(socket_base * sock, const iovec * iov, size_t iovlen);

 

	int turn_tls_send(tls_peer * peer, const sockaddr * addr, socklen_t addr_size, size_t total_len, const iovec * iov, size_t iovlen);

	int turnserver_send_error(int transport_protocol, socket_base * sock, int method, const uint8_t * id, int error, const address_type * saddr, socklen_t saddr_size, unsigned char * key);

 
	int   turnserver_is_address_denied(const uint8_t* addr, size_t addrlen, uint16_t port);

	int  turnserver_process_connectionbind_request(int transport_protocol,
		socket_base* sock, const struct turn_message* message, const address_type* saddr,
		socklen_t saddr_size, struct account_desc* account,
		struct list_head* allocation_list);
	 
};
 
