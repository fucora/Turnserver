#pragma once


#include "commonTypes.h"   
#include "allocation.h"  
#include "turn.h"
#include "socketListener.h"
#include "protocol.h"

class turn_server
{
public:
	turn_server();
	~turn_server();
	int StartServer();

	void onTcpConnect(tcp_socket * tcpsocket);

	void onTcpMessage(buffer_type * buf, int lenth, tcp_socket * tcpsocket);

	void onUdpMessage(buffer_type * buf, int lenth, udp_socket * udpsocket);

	int MessageHandle(buffer_type data, int lenth, int transport_protocol, address_type remoteaddr, address_type localaddr, int remoteAddrSize, socket_base* socket);
	 
	int turnserver_process_channeldata(int transport_protocol, uint16_t channel_number, const char * buf, ssize_t buflen, address_type remoteaddr, address_type localaddr, int remoteAddrSize, list_head * allocation_list);

	int turnserver_check_bandwidth_limit(allocation_desc * desc, size_t byteup, size_t bytedown);

	socklen_t sockaddr_get_size(sockaddr_storage * ss);

	int turnserver_send_error(int transport_protocol, socket_base * sock, int method, const uint8_t * id, int error, address_type remoteaddr, int remoteAddrSize, unsigned char * key);

	int turn_send_message(int transport_protocol, socket_base * sock, address_type remoteaddr, int remoteAddrSize, size_t total_len, const iovec * iov, size_t iovlen);

	int turn_udp_send(socket_base * sock, address_type remoteaddr, int remoteAddrSize, const iovec * iov, size_t iovlen);

	int turn_tcp_send(socket_base * sock, const iovec * iov, size_t iovlen);

 

	int turn_tls_send(tls_peer * peer, const sockaddr * addr, socklen_t addr_size, size_t total_len, const iovec * iov, size_t iovlen);

 

 
	 
};
 
