#pragma once
#ifndef TURNSERVER_H
#define TURNSERVER_H

#include "commonTypes.h"    

#include "allocation.h" 
#include "socketListener.h"

class turn_server
{
public:
	turn_server();
	~turn_server();
	int StartServer();

	void onTcpConnect(tcp_socket * tcpsocket);

	void onTcpMessage(buffer_type * buf, int lenth, tcp_socket * tcpsocket);

	void onUdpMessage(buffer_type * buf, int lenth, udp_socket * udpsocket);

	int MessageHandle_new(buffer_type buf, int lenth, int transport_protocol, socket_base * sock);

	int check_stun_auth(buffer_type buf, int lenth);
	    
};

#endif