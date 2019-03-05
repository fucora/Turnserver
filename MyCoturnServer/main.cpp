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
	printf("�յ�tcp����");
}

void onTcpMessage(sihnalbuffer  data, sock_ptr* remote_socket) {
 
	printf("�յ�tcp��Ϣ");
}

void onUdpMessage(sihnalbuffer  data, udp_endpoint* remote_endpoint) {
	auto x = remote_endpoint->data()->sa_data;
	printf("�յ�udp��Ϣ");
}