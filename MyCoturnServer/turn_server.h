#pragma once
#ifndef TURNSERVER_H
#define TURNSERVER_H

#include "commonTypes.h"   
#include "allocation.h"  
#include "turn.h"
#include "socketListener.h"
//#include "protocol.h"
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

	int MessageHandle(buffer_type buf, int lenth, int transport_protocol, socket_base * sock);
	  
	int turnserver_process_turn(int transport_protocol, socket_base * sock, StunProtocol * protocol, account_desc * account);

	int turnserver_process_channeldata(int transport_protocol, uint16_t channel_number, const char * buf, ssize_t buflen, address_type * remoteaddr, address_type * localaddr, int remoteAddrSize, list_head * allocation_list);

	int turnserver_check_bandwidth_limit(allocation_desc * desc, size_t byteup, size_t bytedown);

	socklen_t sockaddr_get_size(sockaddr_storage * ss);

	int turnserver_process_channelbind_request(int transport_protocol, socket_base * sock, StunProtocol * protocol, allocation_desc * desc);
	 
	int turnserver_process_send_indication(StunProtocol * protocol, allocation_desc * desc);



	int turnserver_is_ipv6_tunneled_address(const uint8_t * addr, size_t addrlen);
	 
	int turnserver_process_connect_request(int transport_protocol, socket_base * sock, StunProtocol * protocol, allocation_desc * desc);

	int turnserver_process_binding_request(int transport_protocol, socket_base * sock, StunProtocol * protocol);
	  
	int turnserver_process_allocate_request(int transport_protocol, socket_base * sock, StunProtocol * protocol, account_desc * account);

	int  turn_server::turnserver_process_createpermission_request(int transport_protocol, socket_base * sock, StunProtocol * protocol, struct allocation_desc* desc);
	 
	int turnserver_process_refresh_request(int transport_protocol, socket_base * sock, StunProtocol * protocol, allocation_desc * desc, account_desc * account);

	int socket_create(enum protocol_type type, const char* addr, uint16_t port, int reuse, int nodelay);

	void turnserver_block_realtime_signal(void);

	void turnserver_unblock_realtime_signal(void);





	int turn_send_message(int transport_protocol, socket_base * sock, const address_type * remoteaddr, int remoteAddrSize, StunProtocol * protocol);

	int turn_send_message(int transport_protocol, socket_base * sock, StunProtocol * protocol);

	int turn_udp_send(socket_base * sock, StunProtocol * protocol);
	 

	int turn_tcp_send(socket_base * sock, StunProtocol * protocol);

	int turn_tls_send(tls_peer * peer, const sockaddr * addr, socklen_t addr_size, size_t total_len, const iovec * iov, size_t iovlen);

	int turnserver_send_error(int transport_protocol, socket_base * sock, int method, const uint8_t * id, int error, unsigned char * key);
	 
	int   turnserver_is_address_denied(const uint8_t* addr, size_t addrlen, uint16_t port);

	int  turn_server::turnserver_process_connectionbind_request(int transport_protocol,
		socket_base * sock, StunProtocol * protocol, struct account_desc* account,
		struct list_head* allocation_list);

};

#endif