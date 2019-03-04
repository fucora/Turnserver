#include <cstdio>
#include "socketListener.h"
#include "main.h"
using namespace std;
int main()
{
	socketListener manager(8888);
	manager.StartSocketListen();
	manager.WhileTcpConnect(onTcpConnect);
	manager.WhileTcpMessage(onTcpMessage);
	manager.WhileUdpMessage(onUdpMessage);
	int i = 0;
	cin >> i;
    return 0;
}


void onTcpConnect(tcp_endpoint* remote_endpoint ) {
	printf("�յ�tcp����");
}

void onTcpMessage(char data[], tcp_endpoint* remote_endpoint) {
	printf("�յ�tcp��Ϣ");
}

void onUdpMessage(char data[], udp_endpoint* remote_endpoint) {
	printf("�յ�udp��Ϣ");
}