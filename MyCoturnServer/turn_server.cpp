
#include "turn_server.h"



turn_server::turn_server()
{
}

turn_server::~turn_server()
{
}

int turn_server::StartServer() {
	socketListener manager(8888);

	manager.onTcpconnected += newDelegate(this, &turn_server::onTcpConnect);

	manager.onTcpReciveData += newDelegate(this, &turn_server::onTcpMessage);

	manager.onUdpReciveData += newDelegate(this, &turn_server::onUdpMessage);

	manager.StartSocketListen();
	return 1;
}
void turn_server::onTcpConnect(tcp_socket* tcpsocket) {
	printf("收到tcp连接");
}

void turn_server::onTcpMessage(buffer_type* buf, int lenth, tcp_socket* tcpsocket) {
	 
	MessageHandle(*buf, lenth);

	/*int method = turn_agreement::stun_get_method_str(buf, lenth);*/
	printf("收到tcp消息");
}

void turn_server::onUdpMessage(buffer_type* buf, int lenth, udp_socket* udpsocket) {
	MessageHandle(*buf, lenth); 
	printf("收到udp消息");
}

void turn_server::MessageHandle(buffer_type data, int lenth)
{

}
