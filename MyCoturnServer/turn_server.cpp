
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

	auto func1 = (void(*)(buffer_type, int , sock_ptr* ))(&turn_server::onTcpMessage);
	manager.WhileTcpMessage(func1);

	auto func2 = (void(*)(buffer_type, int, udp_endpoint*))(&turn_server::onUdpMessage);
	manager.WhileUdpMessage(func2);

	manager.StartSocketListen();
}
void turn_server::onTcpConnect(sock_ptr* remote_socket) {
	printf("收到tcp连接");
}

void turn_server::onTcpMessage(buffer_type buf, int lenth, sock_ptr* remote_socket) {
	SOCKET_TYPE st = TCP_SOCKET;
	
	size_t blen = lenth;
	uint16_t chnum = 0;
	int is_padding_mandatory = 1;

	if (stun_is_channel_message_str(buf, &blen, &chnum, is_padding_mandatory))
	{

	}
	else if (stun_is_command_message_full_check_str()) {

	}
	/*int method = turn_agreement::stun_get_method_str(buf, lenth);*/
	printf("收到tcp消息");
}

void turn_server::onUdpMessage(buffer_type  data, int lenth, udp_endpoint* remote_endpoint) {
	auto x = remote_endpoint->data()->sa_data;
	printf("收到udp消息");
}
