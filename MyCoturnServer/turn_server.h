#pragma once

#include "socketListener.h"
#include "commonTypes.h" 

class turn_server
{
public:
	turn_server();
	~turn_server();
	int StartServer();

	void onTcpConnect(tcp_socket * tcpsocket);

	void onTcpMessage(buffer_type * buf, int lenth, tcp_socket * tcpsocket);

	void onUdpMessage(buffer_type * buf, int lenth, udp_socket * udpsocket);

 

	void MessageHandle(buffer_type data, int lenth); 
	 
};
 
