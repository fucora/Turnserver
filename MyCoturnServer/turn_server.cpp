
#include "turn_server.h"


unsigned long bandwidth = 1024;//带宽
 
char* listen_address = "127.0.0.1";
char* nonce_key = "hieKedq";
int turn_tcp_po = 1;
char* realmstr = "lul.org";
bool is_turn_tcp = true;
int allocation_lifetime = 1800;
int restricted_bandwidth = 10;
int bandwidth_per_allocation = 150;
int max_relay_per_username = 5; 

#define SOFTWARE_DESCRIPTION "TurnServer 1"  
 
//*******************Coturn**********************************************
int can_resume = 1;
int no_stun = 0;
int stun_only = 0;
int secure_stun = 0;
#define MAX_NUMBER_OF_UNKNOWN_ATTRS (128)
//********************************************************************
socketListener manager(8888);
turn_server::turn_server()
{ 
}

turn_server::~turn_server()
{
}

int turn_server::StartServer() {
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
	//boost::asio::posix 
	//address_type remoteaddr = address_type(tcpsocket->remote_endpoint().address());
	//address_type localaddr = address_type(tcpsocket->local_endpoint().address());
	//int remoteAddrSize = tcpsocket->local_endpoint().size();
	MessageHandle_new(*buf, lenth, IPPROTO_TCP, tcpsocket);
	/*int method = turn_agreement::stun_get_method_str(buf, lenth);*/
	printf("收到tcp消息");
}

void turn_server::onUdpMessage(buffer_type* buf, int lenth, udp_socket* udpsocket) {
	//address_type remoteaddr = address_type(udpsocket->remote_endpoint().address());
	//address_type localaddr = address_type(udpsocket->local_endpoint().address());
	//int remoteAddrSize = udpsocket->local_endpoint().size();
	MessageHandle_new(*buf, lenth, IPPROTO_UDP, udpsocket);
	printf("收到udp消息");
}


int turn_server::MessageHandle_new(buffer_type buf, int lenth, int transport_protocol, socket_base* sock)
{
	stun_tid tid;
	size_t blen = lenth;
	size_t orig_blen = lenth;
	int error_code = 0;
	int enforce_fingerprints;
	u16bits chnum = 0;
	const u08bits* in_data = (const u08bits*)buf;
	u16bits ua_num = 0;//unknow_attribute_number
	bool no_response = false;//是否需要创建responese，默认需要创建
	bool resp_constructed = false;//是否创建了response
	bool secure_stun = true;
	bool stun_only = true;
	ioa_engine_handle out_io_handle = (ioa_engine_handle)malloc(sizeof(ioa_engine_handle));

	if (stun_is_channel_message_str(in_data, &blen, &chnum, 1)) {
		//处理channel消息
		return 1;
	}
	//判断消息是否完整
	if (!stun_is_command_message_full_check_str(in_data, lenth, 0, &enforce_fingerprints))
	{
		return -1;
	}

	//完整消息处理： 
	u16bits method = stun_get_method_str(in_data, lenth);
	stun_tid_from_message_str(in_data, lenth, &tid);
	if (method != STUN_METHOD_BINDING)
	{
		no_response = true;
	}
	if (stun_is_request_str(in_data, lenth))
	{
		if (method == STUN_METHOD_BINDING)
		{
			no_response = true;
		}
		else if (method != STUN_METHOD_BINDING && stun_only == true)
		{
			no_response = true;
		}
		else if (method != STUN_METHOD_BINDING || secure_stun == true)
		{
			if (method == STUN_METHOD_ALLOCATE)
			{

			}
		}

		if (error_code != 0 && resp_constructed == false && no_response == false) 
		{

		}
	}
	else if (stun_is_indication_str(in_data, lenth))
	{
		no_response = true;
	}
	else
	{

	}
	//存在unknow_attribbute
	if (ua_num > 0) {

	}
	//需要创建response
	if (no_response == false) {


	}
	else {
		resp_constructed = false;
	}
}

int turn_server::check_stun_auth(buffer_type buf, int lenth)
{
	u08bits usname[STUN_MAX_USERNAME_SIZE + 1];
	u08bits nonce[STUN_MAX_NONCE_SIZE + 1];
	u08bits realm[STUN_MAX_REALM_SIZE + 1];
	size_t alen = 0;
	int new_nonce = 0;
	{
		int generate_new_nonce = 0;
	}
}

//static int handle_turn_command(ts_ur_super_session *ss, ioa_net_data *in_buffer, ioa_network_buffer_handle nbh, int *resp_constructed, int can_resume)
//{
//	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "*********************************handle_turn_command \n", __FUNCTION__, 1);
//	stun_tid tid;
//	int err_code = 0;
//	const u08bits *reason = NULL;
//	int no_response = 0;
//	int message_integrity = 0;
//
//	if (!(ss->client_socket))
//	{
//		return -1;
//	}
//	u16bits unknown_attrs[MAX_NUMBER_OF_UNKNOWN_ATTRS];
//	u16bits ua_num = 0;
//	u16bits method = stun_get_method_str(ioa_network_buffer_data(in_buffer->nbh), ioa_network_buffer_get_size(in_buffer->nbh));
//
//	*resp_constructed = 0;
//	stun_tid_from_message_str(ioa_network_buffer_data(in_buffer->nbh), ioa_network_buffer_get_size(in_buffer->nbh), &tid);
//
//	if (stun_is_request_str(ioa_network_buffer_data(in_buffer->nbh), ioa_network_buffer_get_size(in_buffer->nbh))) 
//	{
//		if ((method == STUN_METHOD_BINDING) && no_stun)
//		{
//			no_response = 1;
//		}
//		else if ((method != STUN_METHOD_BINDING) && stun_only)
//		{
//			no_response = 1;
//		}
//		else if ((method != STUN_METHOD_BINDING) || secure_stun)
//		{
//			if (method == STUN_METHOD_ALLOCATE)
//			{
//				allocation *a = get_allocation_ss(ss);
//				if (is_allocation_valid(a)) {
//					if (!stun_tid_equals(&(a->tid), &tid))
//					{
//						err_code = 437;
//						reason = (const u08bits *)"Mismatched allocation: wrong transaction ID";
//					}
//				}
//				if (!err_code)
//				{
//					SOCKET_TYPE cst = get_ioa_socket_type(ss->client_socket);
//					turn_server_addrs_list_t *asl = server->alternate_servers_list;
//
//					if (((cst == UDP_SOCKET) || (cst == DTLS_SOCKET)) && server->self_udp_balance &&server->aux_servers_list && server->aux_servers_list->size)
//					{
//						asl = server->aux_servers_list;
//					}
//					else if (((cst == TLS_SOCKET) || (cst == DTLS_SOCKET) || (cst == TLS_SCTP_SOCKET)) && server->tls_alternate_servers_list && server->tls_alternate_servers_list->size)
//					{
//						asl = server->tls_alternate_servers_list;
//					}
//					if (asl && asl->size)
//					{
//						turn_mutex_lock(&(asl->m));
//						set_alternate_server(asl, get_local_addr_from_ioa_socket(ss->client_socket), &(server->as_counter), method, &tid, resp_constructed, &err_code, &reason, nbh);
//						turn_mutex_unlock(&(asl->m));
//					}
//				}
//			}
//			/* check that the realm is the same as in the original request */
//			if (ss->origin_set)
//			{
//				stun_attr_ref sar = stun_attr_get_first_str(ioa_network_buffer_data(in_buffer->nbh), ioa_network_buffer_get_size(in_buffer->nbh));
//				int origin_found = 0;
//				int norigins = 0;
//
//				while (sar && !origin_found)
//				{
//					if (stun_attr_get_type(sar) == STUN_ATTRIBUTE_ORIGIN)
//					{
//						int sarlen = stun_attr_get_len(sar);
//						if (sarlen > 0)
//						{
//							++norigins;
//							char *o = (char*)turn_malloc(sarlen + 1);
//							ns_bcopy(stun_attr_get_value(sar), o, sarlen);
//							o[sarlen] = 0;
//							char *corigin = (char*)turn_malloc(STUN_MAX_ORIGIN_SIZE + 1);
//							corigin[0] = 0;
//							if (get_canonic_origin(o, corigin, STUN_MAX_ORIGIN_SIZE) < 0)
//							{
//								TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: Wrong origin format: %s\n", __FUNCTION__, o);
//							}
//							if (!strncmp(ss->origin, corigin, STUN_MAX_ORIGIN_SIZE))
//							{
//								origin_found = 1;
//							}
//							turn_free(corigin, sarlen + 1);
//							turn_free(o, sarlen + 1);
//						}
//					}
//					sar = stun_attr_get_next_str(ioa_network_buffer_data(in_buffer->nbh), ioa_network_buffer_get_size(in_buffer->nbh), sar);
//				}
//
//				if (server->check_origin && *(server->check_origin))
//				{
//					if (ss->origin[0])
//					{
//						if (!origin_found)
//						{
//							err_code = 441;
//							reason = (const u08bits *)"The origin attribute does not match the initial session origin value";
//						}
//					}
//					else if (norigins > 0)
//					{
//						err_code = 441;
//						reason = (const u08bits *)"The origin attribute is empty, does not match the initial session origin value";
//					}
//				}
//			}
//
//			/* get the initial origin value */
//			if (!err_code && !(ss->origin_set) && (method == STUN_METHOD_ALLOCATE))
//			{
//				stun_attr_ref sar = stun_attr_get_first_str(ioa_network_buffer_data(in_buffer->nbh), ioa_network_buffer_get_size(in_buffer->nbh));
//				int origin_found = 0;
//				while (sar && !origin_found)
//				{
//					if (stun_attr_get_type(sar) == STUN_ATTRIBUTE_ORIGIN)
//					{
//						int sarlen = stun_attr_get_len(sar);
//						if (sarlen > 0)
//						{
//							char *o = (char*)turn_malloc(sarlen + 1);
//							ns_bcopy(stun_attr_get_value(sar), o, sarlen);
//							o[sarlen] = 0;
//							char *corigin = (char*)turn_malloc(STUN_MAX_ORIGIN_SIZE + 1);
//							corigin[0] = 0;
//							if (get_canonic_origin(o, corigin, STUN_MAX_ORIGIN_SIZE) < 0)
//							{
//								TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "%s: Wrong origin format: %s\n", __FUNCTION__, o);
//							}
//							strncpy(ss->origin, corigin, STUN_MAX_ORIGIN_SIZE);
//							turn_free(corigin, sarlen + 1);
//							turn_free(o, sarlen + 1);
//							origin_found = get_realm_options_by_origin(ss->origin, &(ss->realm_options));
//						}
//					}
//					sar = stun_attr_get_next_str(ioa_network_buffer_data(in_buffer->nbh), ioa_network_buffer_get_size(in_buffer->nbh), sar);
//				}
//				ss->origin_set = 1;
//			}
//
//			if (!err_code && !(*resp_constructed) && !no_response)
//			{
//				if (method == STUN_METHOD_CONNECTION_BIND)
//				{
//
//				}
//				else if (!(*(server->mobility)) || (method != STUN_METHOD_REFRESH) || is_allocation_valid(get_allocation_ss(ss)))
//				{
//					int postpone_reply = 0;
//					check_stun_auth(server, ss, &tid, resp_constructed, &err_code, &reason, in_buffer, nbh, method, &message_integrity, &postpone_reply, can_resume);
//					if (postpone_reply)
//						no_response = 1;
//				}
//			}
//		}
//
//		if (!err_code && !(*resp_constructed) && !no_response)
//		{
//			switch (method) {
//			case STUN_METHOD_ALLOCATE:
//			{
//				handle_turn_allocate(server, ss, &tid, resp_constructed, &err_code, &reason, unknown_attrs, &ua_num, in_buffer, nbh);
//				break;
//			}
//			case STUN_METHOD_CONNECT:
//				handle_turn_connect(server, ss, &tid, &err_code, &reason, unknown_attrs, &ua_num, in_buffer);
//				if (!err_code)
//				{
//					no_response = 1;
//				}
//				break;
//			case STUN_METHOD_CONNECTION_BIND:
//				handle_turn_connection_bind(server, ss, &tid, resp_constructed, &err_code, &reason, unknown_attrs, &ua_num, in_buffer, nbh, message_integrity, can_resume);
//				break;
//			case STUN_METHOD_REFRESH:
//				handle_turn_refresh(server, ss, &tid, resp_constructed, &err_code, &reason, unknown_attrs, &ua_num, in_buffer, nbh, message_integrity, &no_response, can_resume);
//				break;
//			case STUN_METHOD_CHANNEL_BIND:
//				handle_turn_channel_bind(server, ss, &tid, resp_constructed, &err_code, &reason, unknown_attrs, &ua_num, in_buffer, nbh);
//				break;
//			case STUN_METHOD_CREATE_PERMISSION:
//				handle_turn_create_permission(server, ss, &tid, resp_constructed, &err_code, &reason, unknown_attrs, &ua_num, in_buffer, nbh);
//				break;
//			case STUN_METHOD_BINDING:
//			    {
//				int origin_changed = 0;
//				ioa_addr response_origin;
//				int dest_changed = 0;
//				ioa_addr response_destination;
//
//				handle_turn_binding(server, ss, &tid, resp_constructed, &err_code, &reason,
//					unknown_attrs, &ua_num, in_buffer, nbh,
//					&origin_changed, &response_origin,
//					&dest_changed, &response_destination,
//					0, 0);
//
//				if (*resp_constructed && !err_code && (origin_changed || dest_changed))
//				{
//					const u08bits *field = (const u08bits *)get_version(server);
//					size_t fsz = strlen(get_version(server));
//					size_t len = ioa_network_buffer_get_size(nbh);
//					stun_attr_add_str(ioa_network_buffer_data(nbh), &len, STUN_ATTRIBUTE_SOFTWARE, field, fsz);
//					ioa_network_buffer_set_size(nbh, len);
//					send_turn_message_to(server, nbh, &response_origin, &response_destination);
//					no_response = 1;
//				}
//				break;
//			    }
//			default:
//				TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR, "Unsupported STUN request received, method 0x%x\n", (unsigned int)method);
//			};
//		}
//	}
//	else if (stun_is_indication_str(ioa_network_buffer_data(in_buffer->nbh), ioa_network_buffer_get_size(in_buffer->nbh)))
//	{
//		no_response = 1;
//		int postpone = 0;
//		if (!postpone && !err_code)
//		{
//			switch (method)
//			{
//			case STUN_METHOD_BINDING:
//				//ICE ?
//				break;
//			case STUN_METHOD_SEND:
//				handle_turn_send(server, ss, &err_code, &reason, unknown_attrs, &ua_num, in_buffer);
//				break;
//			case STUN_METHOD_DATA:
//				err_code = 403;
//				break;
//			default:
//				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Unsupported STUN indication received: method 0x%x\n", (unsigned int)method);
//			}
//		}
//	}
//	else
//	{
//		no_response = 1;
//	}
//	if (ss->to_be_closed || !(ss->client_socket) || ioa_socket_tobeclosed(ss->client_socket))
//	{
//		return 0;
//	}
//
//	if (ua_num > 0)
//	{
//		err_code = 420;
//		size_t len = ioa_network_buffer_get_size(nbh);
//		stun_init_error_response_str(method, ioa_network_buffer_data(nbh), &len, err_code, NULL, &tid);
//		stun_attr_add_str(ioa_network_buffer_data(nbh), &len, STUN_ATTRIBUTE_UNKNOWN_ATTRIBUTES, (const u08bits*)unknown_attrs, (ua_num * 2));
//		ioa_network_buffer_set_size(nbh, len);
//		*resp_constructed = 1;
//	}
//
//	if (!no_response)
//	{
//		if (!(*resp_constructed))
//		{
//			if (!err_code)
//			{
//				err_code = 400;
//			}
//			size_t len = ioa_network_buffer_get_size(nbh);
//			stun_init_error_response_str(method, ioa_network_buffer_data(nbh), &len, err_code, reason, &tid);
//			ioa_network_buffer_set_size(nbh, len);
//			*resp_constructed = 1;
//		}
//		{
//			const u08bits *field = (const u08bits *)get_version(server);
//			size_t fsz = strlen(get_version(server));
//			size_t len = ioa_network_buffer_get_size(nbh);
//			stun_attr_add_str(ioa_network_buffer_data(nbh), &len, STUN_ATTRIBUTE_SOFTWARE, field, fsz);
//			ioa_network_buffer_set_size(nbh, len);
//		}
//
//		if (message_integrity)
//		{
//			size_t len = ioa_network_buffer_get_size(nbh);
//			stun_attr_add_integrity_str(server->ct, ioa_network_buffer_data(nbh), &len, ss->hmackey, ss->pwd, SHATYPE_DEFAULT);
//			ioa_network_buffer_set_size(nbh, len);
//		}
//
//		if (err_code)
//		{
//		}
//	}
//	else
//	{
//		*resp_constructed = 0;
//	}
//	return 0;
//}

