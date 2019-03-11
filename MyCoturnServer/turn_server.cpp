
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

#define MAX_NUMBER_OF_UNKNOWN_ATTRS (128)
void turn_server::MessageHandle(buffer_type data, int lenth)
{
	int no_stun = 0;
	int stun_only = 1;
	int secure_stun = 1;
	int origin_set = 0;
	int origin = 1;


	stun_tid tid;
	int err_code = 0;
	const u08bits *reason = NULL;
	int no_response = 0;
	int message_integrity = 0;

	u16bits unknown_attrs[MAX_NUMBER_OF_UNKNOWN_ATTRS];
	u16bits ua_num = 0;
	u16bits method = stun_get_method_str((unsigned char*)data, lenth);
	int resp_constructed = 0;
	stun_tid_from_message_str((unsigned char*)data, lenth, &tid);

	if (stun_is_request_str((unsigned char*)data, lenth)) {

		if ((method == STUN_METHOD_BINDING) && no_stun) {
			no_response = 1;

		}
		else if ((method != STUN_METHOD_BINDING) && stun_only) {
			no_response = 1;
		}
		else if ((method != STUN_METHOD_BINDING) || secure_stun) {
			if (method == STUN_METHOD_ALLOCATE) {

			}

			/* check that the realm is the same as in the original request */
			if (origin_set) {
				stun_attr_ref sar = stun_attr_get_first_str((unsigned char*)data, lenth);

				int origin_found = 0;
				int norigins = 0;

				while (sar && !origin_found) {
					if (stun_attr_get_type(sar) == STUN_ATTRIBUTE_ORIGIN) {
					}
					sar = stun_attr_get_next_str((unsigned char*)data, lenth, sar);
				}
			}

			/* get the initial origin value */
			if (!err_code && !origin_set && (method == STUN_METHOD_ALLOCATE)) {
			}
			if (method == STUN_METHOD_CONNECTION_BIND) {
			}
		}

		if (!err_code && !no_response) {
			switch (method) {
			case STUN_METHOD_ALLOCATE:
				break;
			case STUN_METHOD_CONNECT:
				break;
			case STUN_METHOD_CONNECTION_BIND:
				break;
			case STUN_METHOD_REFRESH:
				break;
			case STUN_METHOD_CHANNEL_BIND:
				break;
			case STUN_METHOD_CREATE_PERMISSION:
				break;
			case STUN_METHOD_BINDING:
				break;
			default:
				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unsupported STUN request received, method 0x%x\n", (unsigned int)method);
			};
		}
	}
	else if (stun_is_indication_str((unsigned char*)data, lenth)) {
		switch (method) {
		case STUN_METHOD_BINDING:
			break;

		case STUN_METHOD_SEND:
			break;

		case STUN_METHOD_DATA:
			break;

		default:
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Unsupported STUN indication received: method 0x%x\n", (unsigned int)method);
		}
	}
	else {
		no_response = 1;
	}


	if (ua_num > 0) {
		err_code = 420;
		size_t len = lenth;
		stun_init_error_response_str(method, (unsigned char*)data, &len, err_code, NULL, &tid);
		stun_attr_add_str((unsigned char*)data, &len, STUN_ATTRIBUTE_UNKNOWN_ATTRIBUTES, (const u08bits*)unknown_attrs, (ua_num * 2));
		ioa_network_buffer_set_size(data, len);
		resp_constructed = 1;
	}

	if (!no_response) {

	}
	else {
		resp_constructed = 0;
	}
}
