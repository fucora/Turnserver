#pragma once
#ifndef TURNSERVER_H
#define TURNSERVER_H

#include "commonTypes.h"    
#include "commonMethod.h" 
#include "socketListener.h"
#include "userSessionsManager.h"

class turn_server
{
public:
	turn_server();
	~turn_server();
	int StartServer();

	void onTcpConnect(tcp_socket * tcpsocket);

	void onTcpMessage(buffer_type * buf, int lenth, tcp_socket * tcpsocket);

	void onUdpMessage(buffer_type * buf, int lenth, udp_socket * udpsocket);
	 
	int MessageHandle_new(buffer_type buf, int lenth, SOCKET_TYPE socket_type, socket_base * sock);

	int check_stun_auth(buffer_type buf, int lenth);

	bool dealAllocation(u16bits method, ioa_network_buffer_handle * out_io_handle, bool * resp_constructed, SOCKET_TYPE socket_type, socket_base * sock, useressionEntity * userSession, stun_tid * currentTid, int * errorCode, const u08bits * reason, size_t * counter);
	 
	bool dealOriginSetting(const u08bits * in_data, int lenth, useressionEntity * userSession, int * errorCode, const u08bits * reason);
	 
	void set_alternate_server(turn_server_addrs_list_t * asl, const ioa_addr * local_addr, size_t * counter, u16bits method, stun_tid * tid, bool * resp_constructed, int * err_code, const u08bits ** reason, ioa_network_buffer_handle nbh);
	 
   
};

#endif