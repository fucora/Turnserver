#pragma once

#include "socketListener.h"
#include "commonTypes.h" 

class turn_server
{
public:
	turn_server();
	~turn_server();
	int StartServer();

	void onTcpConnect(sock_ptr * remote_socket);

	void onTcpMessage(buffer_type* buf, int lenth, sock_ptr * remote_socket);

	void onUdpMessage(buffer_type* data, int lenth, udp_endpoint * remote_endpoint);

	void MessageHandle(buffer_type data, int lenth);
	 
};

