#include "userSessionsManager.h"

vector<useressionEntity> userSessionsManager::userSessions;

userSessionsManager::userSessionsManager()
{
}


userSessionsManager::~userSessionsManager()
{
}


useressionEntity* userSessionsManager::getClientSession(SOCKET_TYPE socket_type, socket_base* sock)
{
	u08bits* clientAddrStr = NULL;
	int clientPort = 0;
	if (socket_type == UDP_SOCKET)
	{
		udp_socket* udp_sock = (udp_socket*)sock;
		clientPort = udp_sock->remote_endpoint().port();
		clientAddrStr = (u08bits*)malloc(udp_sock->remote_endpoint().address().to_string().length());
		memcpy(clientAddrStr, udp_sock->remote_endpoint().address().to_string().data(), udp_sock->remote_endpoint().address().to_string().length());
	}
	else if (socket_type == TCP_SOCKET) {
		tcp_socket* tcp_sock = (tcp_socket*)sock;
		clientPort = tcp_sock->remote_endpoint().port();
		clientAddrStr = (u08bits*)malloc(tcp_sock->remote_endpoint().address().to_string().length());
		memcpy(clientAddrStr, tcp_sock->remote_endpoint().address().to_string().data(), tcp_sock->remote_endpoint().address().to_string().length());
	}
	else
	{
		return NULL;
	}

	int count = userSessions.size();
	for (int i = 0; i < count; i++)
	{
		useressionEntity usersessionm = userSessions.at(i);
		if (usersessionm.client_socket_port == clientPort && strcmp((const char*)usersessionm.client_socket_addr, (const char*)clientAddrStr))
		{
			return &usersessionm;
		}
	}
	useressionEntity* session = (useressionEntity*)malloc(sizeof(useressionEntity));
	session->client_socket_port = clientPort;
	session->client_socket_addr = clientAddrStr;

	userSessions.push_back(*session);
	return session;
}
