#include <cstdio>
#include "socketListener.h"
#include "main.h"
using namespace std;
int main()
{
	socketListener manager(8888);
	manager.WhileTcpConnect(onTcpConnect);
	manager.WhileTcpMessage(onTcpMessage);
	manager.WhileUdpMessage(onUdpMessage);

	manager.StartSocketListen();

	int i = 0;
	cin >> i;
	return 0;
}


void onTcpConnect(sock_ptr* remote_socket) {
	printf("收到tcp连接");
}

void onTcpMessage(buffer_type  data, int lenth, sock_ptr* remote_socket) {
	 
	printf("收到tcp消息");
}

void onUdpMessage(buffer_type  data, int lenth, udp_endpoint* remote_endpoint) {
	auto x = remote_endpoint->data()->sa_data;
	printf("收到udp消息");
}