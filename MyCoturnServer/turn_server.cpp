
#include "turn_server.h"


turn_server::turn_server()
{
}

turn_server::~turn_server()
{
}

int turn_server::StartServer() {
	socketListener manager(8888);

	auto func = (void(*)(sock_ptr *))(&turn_server::onTcpConnect);
	manager.WhileTcpConnect(func);

	auto func1 = (void(*)(buffer_type*, int, sock_ptr*))(&turn_server::onTcpMessage);
	manager.WhileTcpMessage(func1);

	auto func2 = (void(*)(buffer_type*, int, udp_endpoint*))(&turn_server::onUdpMessage);
	manager.WhileUdpMessage(func2);

	manager.StartSocketListen();
	return 1;
}
void turn_server::onTcpConnect(sock_ptr* remote_socket) {
	printf("收到tcp连接");
}

void turn_server::onTcpMessage(buffer_type* buf, int lenth, sock_ptr* remote_socket) {


	MessageHandle(*buf, lenth);

	/*int method = turn_agreement::stun_get_method_str(buf, lenth);*/
	printf("收到tcp消息");
}

void turn_server::onUdpMessage(buffer_type*  buf, int lenth, udp_endpoint* remote_endpoint) {
	MessageHandle(*buf, lenth);
	auto x = remote_endpoint->data()->sa_data;
	printf("收到udp消息");
}
 
void turn_server::MessageHandle(buffer_type data, int lenth)
{
	 
}
