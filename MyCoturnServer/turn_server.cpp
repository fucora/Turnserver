
#include "turn_server.h"


unsigned long bandwidth = 1024;//带宽
list_head* _allocation_list;
char* listen_address = "127.0.0.1";
char* nonce_key = "hieKedq";
int turn_tcp_po = 1;
char* realmstr = "domain.org";
bool is_turn_tcp = true;
int allocation_lifetime = 1800;
int restricted_bandwidth = 10;
int bandwidth_per_allocation = 150;
int max_relay_per_username = 5;
/**
 * \var g_denied_address_list
 * \brief The denied address list.
 */
list_head g_denied_address_list;
/**
 * \var g_tcp_socket_list
 * \brief List which contains remote TCP sockets.
 *
 * This list does not contains TURN-TCP related sockets.
 */
static struct list_head g_tcp_socket_list;
/**
 * \var g_token_list
 * \brief List of valid tokens.
 */
static struct list_head g_token_list;
/**
 * \var g_supported_even_port_flags
 * \brief EVEN-PORT flags supported.
 *
 * For the moment the following flags are supported:
 * - R: reserve couple of ports (one even, one odd).
 */
static const uint8_t g_supported_even_port_flags = 0x80;

#define SOFTWARE_DESCRIPTION "TurnServer 1"  

socketListener manager(8888);

turn_server::turn_server()
{
 

}

turn_server::~turn_server()
{
}

int turn_server::StartServer() {

	auto x = sizeof(uint16_t);


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
	address_type remoteaddr = address_type(tcpsocket->remote_endpoint().address());
	address_type localaddr = address_type(tcpsocket->local_endpoint().address());
	int remoteAddrSize = tcpsocket->local_endpoint().size();

	MessageHandle(*buf, lenth, IPPROTO_TCP, &remoteaddr, &localaddr, remoteAddrSize, tcpsocket);
	/*int method = turn_agreement::stun_get_method_str(buf, lenth);*/
	printf("收到tcp消息");
}

void turn_server::onUdpMessage(buffer_type* buf, int lenth, udp_socket* udpsocket) {
	address_type remoteaddr = address_type(udpsocket->remote_endpoint().address());
	address_type localaddr = address_type(udpsocket->local_endpoint().address());
	int remoteAddrSize = udpsocket->local_endpoint().size();
	MessageHandle(*buf, lenth, IPPROTO_UDP, &remoteaddr, &localaddr, remoteAddrSize, udpsocket);
	printf("收到udp消息");
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int turn_server::MessageHandle(buffer_type data, int lenth, int transport_protocol, address_type* remoteaddr, address_type* localaddr, int remoteAddrSize, socket_base* sock)
{
	StunProtocol protocol(data, lenth);
	if (protocol.IsErrorRequest() == true) {
		return -1;
	}
	auto requestType = protocol.getRequestType();
	auto requestMethod = protocol.getRequestMethod();

	if (STUN_IS_REQUEST(requestType) && requestMethod != STUN_METHOD_BINDING) {
		/* check long-term authentication for all requests except for a STUN
		 * binding request
		 */
		if (!protocol.message_integrity)
		{ 
			StunProtocol* errorMessage;
			unsigned char*  nonce = protocol.get_generate_nonce(nonce_key, strlen(nonce_key));
			try
			{
				debug(DBG_ATTR, "No message integrity\n");
				errorMessage->create_error_response_401(requestMethod, protocol.reuqestHeader->turn_msg_id, realmstr, nonce);
			}
			catch (const std::exception&)
			{
				//turnserver_send_error(transport_protocol, sock, requestMethod, message.msg->turn_msg_id, 500, remoteaddr, remoteAddrSize, NULL);
			} 
			errorMessage->turn_attr_software_create(SOFTWARE_DESCRIPTION); 
		
			errorMessage->turn_attr_fingerprint_create(0); 
			/* convert to big endian */
			errorMessage->reuqestHeader->turn_msg_len = htons(errorMessage->reuqestHeader->turn_msg_len);

		写到了这里
			if (turn_send_message(transport_protocol, sock, remoteaddr, remoteAddrSize, ntohs(error->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, idx) == -1)
			{
				debug(DBG_ATTR, "turn_send_message failed\n");
			}
			/* free sent data */
			iovec_free_data(iov, idx);
			return 0;
		}

	}

}
int turn_server::MessageHandle2(buffer_type data, int lenth, int transport_protocol, address_type* remoteaddr, address_type* localaddr, int remoteAddrSize, socket_base* sock)
{
	StunProtocol protocol(data, lenth);
	return 1;

	struct turn_message message;
	list_head* account_list;
	struct account_desc* account = NULL;
	uint16_t unknown[32];
	size_t unknown_size = sizeof(unknown) / sizeof(uint32_t);
	uint16_t hdr_msg_type = 0;
	size_t total_len = 0;
	uint16_t method = 0;
	uint16_t type = 0;

	if (lenth < 4)
	{
		debug(DBG_ATTR, "Size too short\n");
		return 0;
	}
	memcpy(&type, data, sizeof(uint16_t));
	type = ntohs(type);
	/* is it a ChannelData message (bit 0 and 1 are not set to 0) ? */
	if (TURN_IS_CHANNELDATA(type))
	{
		return turnserver_process_channeldata(transport_protocol, type, data, lenth, remoteaddr, localaddr, remoteAddrSize, _allocation_list);
	}

	if (turn_parse_message(data, lenth, &message, unknown, &unknown_size) == -1)
	{
		debug(DBG_ATTR, "Parse message failed\n");
		return -1;
	}
	/* check if it is a STUN/TURN header */
	if (!message.msg)
	{
		debug(DBG_ATTR, "No STUN/TURN header\n");
		return -1;
	}
	/* convert into host byte order */
	hdr_msg_type = ntohs(message.msg->turn_msg_type);
	total_len = ntohs(message.msg->turn_msg_len) + sizeof(struct turn_msg_hdr);
	/* check if it is a known class */
	if (!STUN_IS_REQUEST(hdr_msg_type) &&
		!STUN_IS_INDICATION(hdr_msg_type) &&
		!STUN_IS_SUCCESS_RESP(hdr_msg_type) &&
		!STUN_IS_ERROR_RESP(hdr_msg_type))
	{
		debug(DBG_ATTR, "Unknown message class\n");
		return -1;
	}

	method = STUN_GET_METHOD(hdr_msg_type);
	/* check that the method value is supported */
	if (method != STUN_METHOD_BINDING &&
		method != TURN_METHOD_ALLOCATE &&
		method != TURN_METHOD_REFRESH &&
		method != TURN_METHOD_CREATEPERMISSION &&
		method != TURN_METHOD_CHANNELBIND &&
		method != TURN_METHOD_SEND &&
		method != TURN_METHOD_DATA &&
		(method != TURN_METHOD_CONNECT || !turn_tcp_po) &&
		(method != TURN_METHOD_CONNECTIONBIND || !turn_tcp_po))
	{
		debug(DBG_ATTR, "Unknown method\n");
		return -1;
	}

	/* check the magic cookie */
	if (message.msg->turn_msg_cookie != htonl(STUN_MAGIC_COOKIE))
	{
		debug(DBG_ATTR, "Bad magic cookie\n");
		return -1;
	}
	/* check the fingerprint if present */
	if (message.fingerprint)
	{
		/* verify if CRC is valid */
		uint32_t crc = 0;
		crc = crc32_generate((const unsigned char*)data, total_len - sizeof(struct turn_attr_fingerprint), 0);
		if (htonl(crc) != (message.fingerprint->turn_attr_crc ^ htonl(STUN_FINGERPRINT_XOR_VALUE)))
		{
			debug(DBG_ATTR, "Fingerprint mismatch\n");
			return -1;
		}
	}
	/* all this cases above discard silently the packets,
	 * so now process the packet more in details
	 */
	if (STUN_IS_REQUEST(hdr_msg_type) && method != STUN_METHOD_BINDING)
	{
		/* check long-term authentication for all requests except for a STUN
		 * binding request
		 */
		if (!message.message_integrity)
		{
			/* no messages integrity => error 401 */
			/* header, error-code, realm, nonce, software */
			struct iovec iov[12];
			uint8_t nonce[48];
			struct turn_msg_hdr* error = NULL;
			struct turn_attr_hdr* attr = NULL;
			size_t idx = 0;
			debug(DBG_ATTR, "No message integrity\n");
			turn_generate_nonce(nonce, sizeof(nonce), (unsigned char*)nonce_key, strlen(nonce_key));
			if (!(error = turn_error_response_401(method, message.msg->turn_msg_id, realmstr, nonce, sizeof(nonce), iov, &idx)))
			{
				turnserver_send_error(transport_protocol, sock, method, message.msg->turn_msg_id, 500, remoteaddr, remoteAddrSize, NULL);
				return -1;
			}

			/* software (not fatal if it cannot be allocated)`````` */
			if ((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION, sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
			{
				error->turn_msg_len += iov[idx].iov_len;
				idx++;
			}

			turn_add_fingerprint(iov, &idx); /* not fatal if not successful */
			/* convert to big endian */
			error->turn_msg_len = htons(error->turn_msg_len);

			if (turn_send_message(transport_protocol, sock, remoteaddr, remoteAddrSize, ntohs(error->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, idx) == -1)
			{
				debug(DBG_ATTR, "turn_send_message failed\n");
			}
			/* free sent data */
			iovec_free_data(iov, idx);
			return 0;
		}

		if (!message.username || !message.realm || !message.nonce)
		{
			/* missing username, realm or nonce => error 400 */
			turnserver_send_error(transport_protocol, sock, method, message.msg->turn_msg_id, 400, remoteaddr, remoteAddrSize, NULL);
			return 0;
		}

		if (turn_nonce_is_stale(message.nonce->turn_attr_nonce, ntohs(message.nonce->turn_attr_len), (unsigned char*)nonce_key, strlen(nonce_key)))
		{
			/* nonce staled => error 438 */
			/* header, error-code, realm, nonce, software */
			struct iovec iov[5];
			size_t idx = 0;
			struct turn_msg_hdr* error = NULL;
			struct turn_attr_hdr* attr = NULL;
			uint8_t nonce[48];

			turn_generate_nonce(nonce, sizeof(nonce), (unsigned char*)nonce_key, strlen(nonce_key));
			idx = 0;

			if (!(error = turn_error_response_438(method, message.msg->turn_msg_id, realmstr, nonce, sizeof(nonce), iov, &idx)))
			{
				turnserver_send_error(transport_protocol, sock, method, message.msg->turn_msg_id, 500, remoteaddr, remoteAddrSize, NULL);
				return -1;
			}
			/* software (not fatal if it cannot be allocated) */
			if ((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION,
				sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
			{
				error->turn_msg_len += iov[idx].iov_len;
				idx++;
			}
			/* convert to big endian */
			error->turn_msg_len = htons(error->turn_msg_len);

			if (turn_send_message(transport_protocol, sock, remoteaddr, remoteAddrSize, ntohs(error->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, idx) == -1)
			{
				debug(DBG_ATTR, "turn_send_message failed\n");
			}
			/* free sent data */
			iovec_free_data(iov, idx);
			return 0;
		}
		/* find the desired username and password in the account list */
		{
			char username[514];
			char user_realm[256];
			size_t username_len = ntohs(message.username->turn_attr_len) + 1;
			size_t realm_len = ntohs(message.realm->turn_attr_len) + 1;

			if (username_len > 513 || realm_len > 256)
			{
				/* some attributes are too long */
				turnserver_send_error(transport_protocol, sock, method, message.msg->turn_msg_id, 400, remoteaddr, remoteAddrSize, NULL);
				return -1;
			}

			strncpy(username, (char*)message.username->turn_attr_username, username_len);
			username[username_len - 1] = 0x00;
			strncpy(user_realm, (char*)message.realm->turn_attr_realm, realm_len);
			user_realm[realm_len - 1] = 0x00;
			/* search the account */
			account = account_list_find(_allocation_list, username, user_realm);

			if (!account)
			{
				/* not valid username => error 401 */
				struct iovec iov[5]; /* header, error-code, realm, nonce, software */
				size_t idx = 0;
				struct turn_msg_hdr* error = NULL;
				struct turn_attr_hdr* attr = NULL;
				uint8_t nonce[48];

				debug(DBG_ATTR, "No account\n");
				turn_generate_nonce(nonce, sizeof(nonce), (unsigned char*)nonce_key, strlen(nonce_key));
				idx = 0;

				if (!(error = turn_error_response_401(method, message.msg->turn_msg_id, realmstr, nonce, sizeof(nonce), iov, &idx)))
				{
					turnserver_send_error(transport_protocol, sock, method, message.msg->turn_msg_id, 500, remoteaddr, remoteAddrSize, NULL);
					return -1;
				}
				/* software (not fatal if it cannot be allocated) */
				if ((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION, sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
				{
					error->turn_msg_len += iov[idx].iov_len;
					idx++;
				}

				turn_add_fingerprint(iov, &idx); /* not fatal if not successful */
				/* convert to big endian */
				error->turn_msg_len = htons(error->turn_msg_len);
				if (turn_send_message(transport_protocol, sock, remoteaddr, remoteAddrSize, ntohs(error->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, idx) == -1)
				{
					debug(DBG_ATTR, "turn_send_message failed\n");
				}
				/* free sent data */
				iovec_free_data(iov, idx);
				return 0;
			}
		}
		/* compute HMAC-SHA1 and compare with the value in message_integrity */
		{
			uint8_t hash[20];

			if (message.fingerprint)
			{
				/* if the message contains a FINGERPRINT attribute, adjust the size */
				size_t len_save = message.msg->turn_msg_len;
				message.msg->turn_msg_len = ntohs(message.msg->turn_msg_len) - sizeof(struct turn_attr_fingerprint);

				message.msg->turn_msg_len = htons(message.msg->turn_msg_len);
				turn_calculate_integrity_hmac((const unsigned char*)data,
					total_len - sizeof(struct turn_attr_fingerprint) -
					sizeof(struct turn_attr_message_integrity), account->key,
					sizeof(account->key), hash);

				/* restore length */
				message.msg->turn_msg_len = len_save;
			}
			else
			{
				turn_calculate_integrity_hmac((const unsigned char*)data, total_len - sizeof(struct turn_attr_message_integrity), account->key, sizeof(account->key), hash);
			}

			if (memcmp(hash, message.message_integrity->turn_attr_hmac, 20) != 0)
			{
				/* integrity does not match => error 401 */
				struct iovec iov[5]; /* header, error-code, realm, nonce, software */
				size_t idx = 0;
				struct turn_msg_hdr* error = NULL;
				struct turn_attr_hdr* attr = NULL;
				uint8_t nonce[48];

				debug(DBG_ATTR, "Hash mismatch\n");
#ifndef NDEBUG
				/* print computed hash and the one from the message */
				digest_print(hash, 20);
				digest_print(message.message_integrity->turn_attr_hmac, 20);
#endif
				turn_generate_nonce(nonce, sizeof(nonce), (unsigned char*)nonce_key, strlen(nonce_key));
				idx = 0;

				if (!(error = turn_error_response_401(method, message.msg->turn_msg_id, realmstr, nonce, sizeof(nonce), iov, &idx)))
				{
					turnserver_send_error(transport_protocol, sock, method, message.msg->turn_msg_id, 500, remoteaddr, remoteAddrSize, NULL);
					return -1;
				}

				/* software (not fatal if it cannot be allocated) */
				if ((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION,
					sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
				{
					error->turn_msg_len += iov[idx].iov_len;
					idx++;
				}

				turn_add_fingerprint(iov, &idx); /* not fatal if not successful */

				/* convert to big endian */
				error->turn_msg_len = htons(error->turn_msg_len);

				if (turn_send_message(transport_protocol, sock, remoteaddr, remoteAddrSize, ntohs(error->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, idx) == -1)
				{
					debug(DBG_ATTR, "turn_send_message failed\n");
				}

				/* free sent data */
				iovec_free_data(iov, idx);
				return 0;
			}
		}
	}
	/* check if there are unknown comprehension-required attributes */
	if (unknown_size)
	{
		struct iovec iov[4]; /* header, error-code, unknown-attributes, software */
		size_t idx = 0;
		struct turn_msg_hdr* error = NULL;
		struct turn_attr_hdr* attr = NULL;

		/* if not a request, message is discarded */
		if (!STUN_IS_REQUEST(hdr_msg_type))
		{
			debug(DBG_ATTR, "message has unknown attribute and it is not a request, "
				"discard\n");
			return -1;
		}

		/* unknown attributes found => error 420 */
		if (!(error = turn_error_response_420(method, message.msg->turn_msg_id,
			unknown, unknown_size, iov, &idx)))
		{
			turnserver_send_error(transport_protocol, sock, method,
				message.msg->turn_msg_id, 500, remoteaddr, remoteAddrSize,
				account ? account->key : NULL);
			return -1;
		}

		/* software (not fatal if it cannot be allocated) */
		if ((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION,
			sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
		{
			error->turn_msg_len += iov[idx].iov_len;
			idx++;
		}

		/* convert to big endian */
		error->turn_msg_len = htons(error->turn_msg_len);

		if (turn_send_message(transport_protocol, sock, remoteaddr, remoteAddrSize,
			ntohs(error->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, idx)
			== -1)
		{
			debug(DBG_ATTR, "turn_send_message failed\n");
		}

		/* free sent data */
		iovec_free_data(iov, idx);
		return 0;
	}

	/* the basic checks are done,
	 * now check that specific method requirement are OK
	 */
	debug(DBG_ATTR, "OK basic validation are done, process the TURN message\n");
	return turnserver_process_turn(transport_protocol, sock, &message, remoteaddr, localaddr, remoteAddrSize, account);
}

/**
 * \brief Process a TURN request.
 * \param transport_protocol transport protocol used
 * \param sock socket
 * \param message TURN message
 * \param saddr source address of the message
 * \param daddr destination address of the message
 * \param saddr_size sizeof addr
 * \param allocation_list list of allocations
 * \param account account descriptor (may be NULL)
 * \param speer TLS peer, if not NULL the connection is in TLS so response is
 * also in TLS
 * \return 0 if success, -1 otherwise
 */
int turn_server::turnserver_process_turn(int transport_protocol, socket_base* sock,
	const struct turn_message* message, const address_type* saddr,
	const address_type* daddr, socklen_t saddr_size, struct account_desc* account)
{
	uint16_t hdr_msg_type = 0;
	uint16_t method = 0;
	struct allocation_desc* desc = NULL;
	debug(DBG_ATTR, "Process a TURN message\n");
	hdr_msg_type = ntohs(message->msg->turn_msg_type);
	method = STUN_GET_METHOD(hdr_msg_type);
	/* process STUN binding request */
	if (STUN_IS_REQUEST(hdr_msg_type) && method == STUN_METHOD_BINDING)
	{
		return turnserver_process_binding_request(transport_protocol, sock, message, saddr, saddr_size);
	}
	/* RFC6062 (TURN-TCP) */
	/* find right tuple for a TCP allocation (ConnectionBind case) */
	if (STUN_IS_REQUEST(hdr_msg_type) && method == TURN_METHOD_CONNECTIONBIND)
	{
		/* ConnectionBind is only for TCP or TLS over TCP <-> TCP */
		if (transport_protocol == IPPROTO_TCP)
		{
			return turnserver_process_connectionbind_request(transport_protocol, sock, message, saddr, saddr_size, account, _allocation_list);
		}
		else
		{
			return turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 400, saddr, saddr_size, account->key);
		}
	}
	/* check the 5-tuple except for an Allocate request */
	if (method != TURN_METHOD_ALLOCATE)
	{
		desc = allocation_list_find_tuple(_allocation_list, transport_protocol, daddr, saddr, saddr_size);
		if (STUN_IS_REQUEST(hdr_msg_type))
		{
			/* check for the allocated username */
			if (desc && message->username && message->realm)
			{
				size_t len = ntohs(message->username->turn_attr_len);
				size_t rlen = ntohs(message->realm->turn_attr_len);
				if (len != strlen(desc->username) ||
					strncmp((char*)message->username->turn_attr_username,
						desc->username, len) ||
					rlen != strlen(desc->realm) ||
					strncmp((char*)message->realm->turn_attr_realm, desc->realm, rlen))
				{
					desc = NULL;
				}
			}
			else
			{
				desc = NULL;
			}
		}
		if (!desc)
		{
			/* reject with error 437 if it a request, ignored otherwise */
			/* the refresh function will handle this case */
			if (STUN_IS_REQUEST(hdr_msg_type))
			{
				/* allocation mismatch => error 437 */
				turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 437, saddr, saddr_size, account->key);
				return 0;
			}

			debug(DBG_ATTR, "No valid 5-tuple match\n");
			return -1;
		}
		/* update allocation nonce */
		if (message->nonce)
		{
			memcpy(desc->nonce, message->nonce->turn_attr_nonce, 24);
		}
	}

	if (STUN_IS_REQUEST(hdr_msg_type))
	{
		if (method != TURN_METHOD_ALLOCATE)
		{
			/* check to prevent hijacking the client's allocation */
			size_t len = strlen(account->username);
			size_t rlen = strlen(account->realm);
			if (len != ntohs(message->username->turn_attr_len) ||
				strncmp((char*)message->username->turn_attr_username,
					account->username, len) ||
				rlen != ntohs(message->realm->turn_attr_len) ||
				strncmp((char*)message->realm->turn_attr_realm, account->realm, rlen))
			{
				/* credentials do not match with those used for allocation
				 * => error 441
				 */
				debug(DBG_ATTR, "Wrong credentials!\n");
				turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 441, saddr, saddr_size, account->key);
				return 0;
			}
		}

		switch (method)
		{
		case TURN_METHOD_ALLOCATE:
			turnserver_process_allocate_request(transport_protocol, sock, message, saddr, daddr, saddr_size, account);
			break;
		case TURN_METHOD_REFRESH:
			turnserver_process_refresh_request(transport_protocol, sock, message, saddr, saddr_size, desc, account);
			break;
		case TURN_METHOD_CREATEPERMISSION:
			turnserver_process_createpermission_request(transport_protocol, sock, message, saddr, saddr_size, desc);
			break;
		case TURN_METHOD_CHANNELBIND:
			/* ChannelBind is only for UDP relay */
			if (desc->relayed_transport_protocol == IPPROTO_UDP)
			{
				turnserver_process_channelbind_request(transport_protocol, sock, message, saddr, saddr_size, desc);
			}
			else
			{
				turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 400, saddr, saddr_size, desc->key);
			}
			break;
		case TURN_METHOD_CONNECT: /* RFC6062 (TURN-TCP) */
		  /* Connect is only for TCP or TLS over TCP <-> TCP */
			if (transport_protocol == IPPROTO_TCP && desc->relayed_transport_protocol == IPPROTO_TCP)
			{
				turnserver_process_connect_request(transport_protocol, sock, message, saddr, saddr_size, desc);
			}
			else
			{
				turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 400, saddr, saddr_size, desc->key);
			}
			break;
		default:
			return -1;
			break;
		}
	}
	else if (STUN_IS_SUCCESS_RESP(hdr_msg_type) || STUN_IS_ERROR_RESP(hdr_msg_type))
	{
		/* should not happen */
	}
	else if (STUN_IS_INDICATION(hdr_msg_type))
	{
		switch (method)
		{
		case TURN_METHOD_SEND:
			if (desc->relayed_transport_protocol == IPPROTO_UDP)
			{
				turnserver_process_send_indication(message, desc);
			}
			break;
		case TURN_METHOD_DATA:
			/* should not happen */
			return -1;
			break;
		}
	}

	return 0;
}



////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int turn_server::MessageHandle(buffer_type data, int lenth, int transport_protocol, address_type* remoteaddr, address_type* localaddr, int remoteAddrSize, socket_base* sock)
{
	StunProtocol protocol(data, lenth);
	return 1;

	struct turn_message message;
	list_head* account_list;
	struct account_desc* account = NULL;
	uint16_t unknown[32];
	size_t unknown_size = sizeof(unknown) / sizeof(uint32_t);
	uint16_t hdr_msg_type = 0;
	size_t total_len = 0;
	uint16_t method = 0;
	uint16_t type = 0;

	if (lenth < 4)
	{
		debug(DBG_ATTR, "Size too short\n");
		return 0;
	}
	memcpy(&type, data, sizeof(uint16_t));
	type = ntohs(type);
	/* is it a ChannelData message (bit 0 and 1 are not set to 0) ? */
	if (TURN_IS_CHANNELDATA(type))
	{
		return turnserver_process_channeldata(transport_protocol, type, data, lenth, remoteaddr, localaddr, remoteAddrSize, _allocation_list);
	}

	if (turn_parse_message(data, lenth, &message, unknown, &unknown_size) == -1)
	{
		debug(DBG_ATTR, "Parse message failed\n");
		return -1;
	}
	/* check if it is a STUN/TURN header */
	if (!message.msg)
	{
		debug(DBG_ATTR, "No STUN/TURN header\n");
		return -1;
	}
	/* convert into host byte order */
	hdr_msg_type = ntohs(message.msg->turn_msg_type);
	total_len = ntohs(message.msg->turn_msg_len) + sizeof(struct turn_msg_hdr);
	/* check if it is a known class */
	if (!STUN_IS_REQUEST(hdr_msg_type) &&
		!STUN_IS_INDICATION(hdr_msg_type) &&
		!STUN_IS_SUCCESS_RESP(hdr_msg_type) &&
		!STUN_IS_ERROR_RESP(hdr_msg_type))
	{
		debug(DBG_ATTR, "Unknown message class\n");
		return -1;
	}

	method = STUN_GET_METHOD(hdr_msg_type);
	/* check that the method value is supported */
	if (method != STUN_METHOD_BINDING &&
		method != TURN_METHOD_ALLOCATE &&
		method != TURN_METHOD_REFRESH &&
		method != TURN_METHOD_CREATEPERMISSION &&
		method != TURN_METHOD_CHANNELBIND &&
		method != TURN_METHOD_SEND &&
		method != TURN_METHOD_DATA &&
		(method != TURN_METHOD_CONNECT || !turn_tcp_po) &&
		(method != TURN_METHOD_CONNECTIONBIND || !turn_tcp_po))
	{
		debug(DBG_ATTR, "Unknown method\n");
		return -1;
	}

	/* check the magic cookie */
	if (message.msg->turn_msg_cookie != htonl(STUN_MAGIC_COOKIE))
	{
		debug(DBG_ATTR, "Bad magic cookie\n");
		return -1;
	}
	/* check the fingerprint if present */
	if (message.fingerprint)
	{
		/* verify if CRC is valid */
		uint32_t crc = 0;
		crc = crc32_generate((const unsigned char*)data, total_len - sizeof(struct turn_attr_fingerprint), 0);
		if (htonl(crc) != (message.fingerprint->turn_attr_crc ^ htonl(STUN_FINGERPRINT_XOR_VALUE)))
		{
			debug(DBG_ATTR, "Fingerprint mismatch\n");
			return -1;
		}
	}
	/* all this cases above discard silently the packets,
	 * so now process the packet more in details
	 */
	if (STUN_IS_REQUEST(hdr_msg_type) && method != STUN_METHOD_BINDING)
	{
		/* check long-term authentication for all requests except for a STUN
		 * binding request
		 */
		if (!message.message_integrity)
		{
			/* no messages integrity => error 401 */
			/* header, error-code, realm, nonce, software */
			struct iovec iov[12];
			uint8_t nonce[48];
			struct turn_msg_hdr* error = NULL;
			struct turn_attr_hdr* attr = NULL;
			size_t idx = 0;
			debug(DBG_ATTR, "No message integrity\n");
			turn_generate_nonce(nonce, sizeof(nonce), (unsigned char*)nonce_key, strlen(nonce_key));
			if (!(error = turn_error_response_401(method, message.msg->turn_msg_id, realmstr, nonce, sizeof(nonce), iov, &idx)))
			{
				turnserver_send_error(transport_protocol, sock, method, message.msg->turn_msg_id, 500, remoteaddr, remoteAddrSize, NULL);
				return -1;
			}

			/* software (not fatal if it cannot be allocated)`````` */
			if ((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION, sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
			{
				error->turn_msg_len += iov[idx].iov_len;
				idx++;
			}

			turn_add_fingerprint(iov, &idx); /* not fatal if not successful */
			/* convert to big endian */
			error->turn_msg_len = htons(error->turn_msg_len);

			if (turn_send_message(transport_protocol, sock, remoteaddr, remoteAddrSize, ntohs(error->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, idx) == -1)
			{
				debug(DBG_ATTR, "turn_send_message failed\n");
			}
			/* free sent data */
			iovec_free_data(iov, idx);
			return 0;
		}

		if (!message.username || !message.realm || !message.nonce)
		{
			/* missing username, realm or nonce => error 400 */
			turnserver_send_error(transport_protocol, sock, method, message.msg->turn_msg_id, 400, remoteaddr, remoteAddrSize, NULL);
			return 0;
		}

		if (turn_nonce_is_stale(message.nonce->turn_attr_nonce, ntohs(message.nonce->turn_attr_len), (unsigned char*)nonce_key, strlen(nonce_key)))
		{
			/* nonce staled => error 438 */
			/* header, error-code, realm, nonce, software */
			struct iovec iov[5];
			size_t idx = 0;
			struct turn_msg_hdr* error = NULL;
			struct turn_attr_hdr* attr = NULL;
			uint8_t nonce[48];

			turn_generate_nonce(nonce, sizeof(nonce), (unsigned char*)nonce_key, strlen(nonce_key));
			idx = 0;

			if (!(error = turn_error_response_438(method, message.msg->turn_msg_id, realmstr, nonce, sizeof(nonce), iov, &idx)))
			{
				turnserver_send_error(transport_protocol, sock, method, message.msg->turn_msg_id, 500, remoteaddr, remoteAddrSize, NULL);
				return -1;
			}
			/* software (not fatal if it cannot be allocated) */
			if ((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION,
				sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
			{
				error->turn_msg_len += iov[idx].iov_len;
				idx++;
			}
			/* convert to big endian */
			error->turn_msg_len = htons(error->turn_msg_len);

			if (turn_send_message(transport_protocol, sock, remoteaddr, remoteAddrSize, ntohs(error->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, idx) == -1)
			{
				debug(DBG_ATTR, "turn_send_message failed\n");
			}
			/* free sent data */
			iovec_free_data(iov, idx);
			return 0;
		}
		/* find the desired username and password in the account list */
		{
			char username[514];
			char user_realm[256];
			size_t username_len = ntohs(message.username->turn_attr_len) + 1;
			size_t realm_len = ntohs(message.realm->turn_attr_len) + 1;

			if (username_len > 513 || realm_len > 256)
			{
				/* some attributes are too long */
				turnserver_send_error(transport_protocol, sock, method, message.msg->turn_msg_id, 400, remoteaddr, remoteAddrSize, NULL);
				return -1;
			}

			strncpy(username, (char*)message.username->turn_attr_username, username_len);
			username[username_len - 1] = 0x00;
			strncpy(user_realm, (char*)message.realm->turn_attr_realm, realm_len);
			user_realm[realm_len - 1] = 0x00;
			/* search the account */
			account = account_list_find(_allocation_list, username, user_realm);

			if (!account)
			{
				/* not valid username => error 401 */
				struct iovec iov[5]; /* header, error-code, realm, nonce, software */
				size_t idx = 0;
				struct turn_msg_hdr* error = NULL;
				struct turn_attr_hdr* attr = NULL;
				uint8_t nonce[48];

				debug(DBG_ATTR, "No account\n");
				turn_generate_nonce(nonce, sizeof(nonce), (unsigned char*)nonce_key, strlen(nonce_key));
				idx = 0;

				if (!(error = turn_error_response_401(method, message.msg->turn_msg_id, realmstr, nonce, sizeof(nonce), iov, &idx)))
				{
					turnserver_send_error(transport_protocol, sock, method, message.msg->turn_msg_id, 500, remoteaddr, remoteAddrSize, NULL);
					return -1;
				}
				/* software (not fatal if it cannot be allocated) */
				if ((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION, sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
				{
					error->turn_msg_len += iov[idx].iov_len;
					idx++;
				}

				turn_add_fingerprint(iov, &idx); /* not fatal if not successful */
				/* convert to big endian */
				error->turn_msg_len = htons(error->turn_msg_len);
				if (turn_send_message(transport_protocol, sock, remoteaddr, remoteAddrSize, ntohs(error->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, idx) == -1)
				{
					debug(DBG_ATTR, "turn_send_message failed\n");
				}
				/* free sent data */
				iovec_free_data(iov, idx);
				return 0;
			}
		}
		/* compute HMAC-SHA1 and compare with the value in message_integrity */
		{
			uint8_t hash[20];

			if (message.fingerprint)
			{
				/* if the message contains a FINGERPRINT attribute, adjust the size */
				size_t len_save = message.msg->turn_msg_len;
				message.msg->turn_msg_len = ntohs(message.msg->turn_msg_len) - sizeof(struct turn_attr_fingerprint);

				message.msg->turn_msg_len = htons(message.msg->turn_msg_len);
				turn_calculate_integrity_hmac((const unsigned char*)data,
					total_len - sizeof(struct turn_attr_fingerprint) -
					sizeof(struct turn_attr_message_integrity), account->key,
					sizeof(account->key), hash);

				/* restore length */
				message.msg->turn_msg_len = len_save;
			}
			else
			{
				turn_calculate_integrity_hmac((const unsigned char*)data, total_len - sizeof(struct turn_attr_message_integrity), account->key, sizeof(account->key), hash);
			}

			if (memcmp(hash, message.message_integrity->turn_attr_hmac, 20) != 0)
			{
				/* integrity does not match => error 401 */
				struct iovec iov[5]; /* header, error-code, realm, nonce, software */
				size_t idx = 0;
				struct turn_msg_hdr* error = NULL;
				struct turn_attr_hdr* attr = NULL;
				uint8_t nonce[48];

				debug(DBG_ATTR, "Hash mismatch\n");
#ifndef NDEBUG
				/* print computed hash and the one from the message */
				digest_print(hash, 20);
				digest_print(message.message_integrity->turn_attr_hmac, 20);
#endif
				turn_generate_nonce(nonce, sizeof(nonce), (unsigned char*)nonce_key, strlen(nonce_key));
				idx = 0;

				if (!(error = turn_error_response_401(method, message.msg->turn_msg_id, realmstr, nonce, sizeof(nonce), iov, &idx)))
				{
					turnserver_send_error(transport_protocol, sock, method, message.msg->turn_msg_id, 500, remoteaddr, remoteAddrSize, NULL);
					return -1;
				}

				/* software (not fatal if it cannot be allocated) */
				if ((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION,
					sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
				{
					error->turn_msg_len += iov[idx].iov_len;
					idx++;
				}

				turn_add_fingerprint(iov, &idx); /* not fatal if not successful */

				/* convert to big endian */
				error->turn_msg_len = htons(error->turn_msg_len);

				if (turn_send_message(transport_protocol, sock, remoteaddr, remoteAddrSize, ntohs(error->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, idx) == -1)
				{
					debug(DBG_ATTR, "turn_send_message failed\n");
				}

				/* free sent data */
				iovec_free_data(iov, idx);
				return 0;
			}
		}
	}
	/* check if there are unknown comprehension-required attributes */
	if (unknown_size)
	{
		struct iovec iov[4]; /* header, error-code, unknown-attributes, software */
		size_t idx = 0;
		struct turn_msg_hdr* error = NULL;
		struct turn_attr_hdr* attr = NULL;

		/* if not a request, message is discarded */
		if (!STUN_IS_REQUEST(hdr_msg_type))
		{
			debug(DBG_ATTR, "message has unknown attribute and it is not a request, "
				"discard\n");
			return -1;
		}

		/* unknown attributes found => error 420 */
		if (!(error = turn_error_response_420(method, message.msg->turn_msg_id,
			unknown, unknown_size, iov, &idx)))
		{
			turnserver_send_error(transport_protocol, sock, method,
				message.msg->turn_msg_id, 500, remoteaddr, remoteAddrSize,
				account ? account->key : NULL);
			return -1;
		}

		/* software (not fatal if it cannot be allocated) */
		if ((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION,
			sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
		{
			error->turn_msg_len += iov[idx].iov_len;
			idx++;
		}

		/* convert to big endian */
		error->turn_msg_len = htons(error->turn_msg_len);

		if (turn_send_message(transport_protocol, sock, remoteaddr, remoteAddrSize,
			ntohs(error->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, idx)
			== -1)
		{
			debug(DBG_ATTR, "turn_send_message failed\n");
		}

		/* free sent data */
		iovec_free_data(iov, idx);
		return 0;
	}

	/* the basic checks are done,
	 * now check that specific method requirement are OK
	 */
	debug(DBG_ATTR, "OK basic validation are done, process the TURN message\n");
	return turnserver_process_turn(transport_protocol, sock, &message, remoteaddr, localaddr, remoteAddrSize, account);
}

/**
 * \brief Process a TURN request.
 * \param transport_protocol transport protocol used
 * \param sock socket
 * \param message TURN message
 * \param saddr source address of the message
 * \param daddr destination address of the message
 * \param saddr_size sizeof addr
 * \param allocation_list list of allocations
 * \param account account descriptor (may be NULL)
 * \param speer TLS peer, if not NULL the connection is in TLS so response is
 * also in TLS
 * \return 0 if success, -1 otherwise
 */
int turn_server::turnserver_process_turn(int transport_protocol, socket_base* sock,
	const struct turn_message* message, const address_type* saddr,
	const address_type* daddr, socklen_t saddr_size, struct account_desc* account)
{
	uint16_t hdr_msg_type = 0;
	uint16_t method = 0;
	struct allocation_desc* desc = NULL;
	debug(DBG_ATTR, "Process a TURN message\n");
	hdr_msg_type = ntohs(message->msg->turn_msg_type);
	method = STUN_GET_METHOD(hdr_msg_type);
	/* process STUN binding request */
	if (STUN_IS_REQUEST(hdr_msg_type) && method == STUN_METHOD_BINDING)
	{
		return turnserver_process_binding_request(transport_protocol, sock, message, saddr, saddr_size);
	}
	/* RFC6062 (TURN-TCP) */
	/* find right tuple for a TCP allocation (ConnectionBind case) */
	if (STUN_IS_REQUEST(hdr_msg_type) && method == TURN_METHOD_CONNECTIONBIND)
	{
		/* ConnectionBind is only for TCP or TLS over TCP <-> TCP */
		if (transport_protocol == IPPROTO_TCP)
		{
			return turnserver_process_connectionbind_request(transport_protocol, sock, message, saddr, saddr_size, account, _allocation_list);
		}
		else
		{
			return turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 400, saddr, saddr_size, account->key);
		}
	}
	/* check the 5-tuple except for an Allocate request */
	if (method != TURN_METHOD_ALLOCATE)
	{
		desc = allocation_list_find_tuple(_allocation_list, transport_protocol, daddr, saddr, saddr_size);
		if (STUN_IS_REQUEST(hdr_msg_type))
		{
			/* check for the allocated username */
			if (desc && message->username && message->realm)
			{
				size_t len = ntohs(message->username->turn_attr_len);
				size_t rlen = ntohs(message->realm->turn_attr_len);
				if (len != strlen(desc->username) ||
					strncmp((char*)message->username->turn_attr_username,
						desc->username, len) ||
					rlen != strlen(desc->realm) ||
					strncmp((char*)message->realm->turn_attr_realm, desc->realm, rlen))
				{
					desc = NULL;
				}
			}
			else
			{
				desc = NULL;
			}
		}
		if (!desc)
		{
			/* reject with error 437 if it a request, ignored otherwise */
			/* the refresh function will handle this case */
			if (STUN_IS_REQUEST(hdr_msg_type))
			{
				/* allocation mismatch => error 437 */
				turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 437, saddr, saddr_size, account->key);
				return 0;
			}

			debug(DBG_ATTR, "No valid 5-tuple match\n");
			return -1;
		}
		/* update allocation nonce */
		if (message->nonce)
		{
			memcpy(desc->nonce, message->nonce->turn_attr_nonce, 24);
		}
	}

	if (STUN_IS_REQUEST(hdr_msg_type))
	{
		if (method != TURN_METHOD_ALLOCATE)
		{
			/* check to prevent hijacking the client's allocation */
			size_t len = strlen(account->username);
			size_t rlen = strlen(account->realm);
			if (len != ntohs(message->username->turn_attr_len) ||
				strncmp((char*)message->username->turn_attr_username,
					account->username, len) ||
				rlen != ntohs(message->realm->turn_attr_len) ||
				strncmp((char*)message->realm->turn_attr_realm, account->realm, rlen))
			{
				/* credentials do not match with those used for allocation
				 * => error 441
				 */
				debug(DBG_ATTR, "Wrong credentials!\n");
				turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 441, saddr, saddr_size, account->key);
				return 0;
			}
		}

		switch (method)
		{
		case TURN_METHOD_ALLOCATE:
			turnserver_process_allocate_request(transport_protocol, sock, message, saddr, daddr, saddr_size, account);
			break;
		case TURN_METHOD_REFRESH:
			turnserver_process_refresh_request(transport_protocol, sock, message, saddr, saddr_size, desc, account);
			break;
		case TURN_METHOD_CREATEPERMISSION:
			turnserver_process_createpermission_request(transport_protocol, sock, message, saddr, saddr_size, desc);
			break;
		case TURN_METHOD_CHANNELBIND:
			/* ChannelBind is only for UDP relay */
			if (desc->relayed_transport_protocol == IPPROTO_UDP)
			{
				turnserver_process_channelbind_request(transport_protocol, sock, message, saddr, saddr_size, desc);
			}
			else
			{
				turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 400, saddr, saddr_size, desc->key);
			}
			break;
		case TURN_METHOD_CONNECT: /* RFC6062 (TURN-TCP) */
		  /* Connect is only for TCP or TLS over TCP <-> TCP */
			if (transport_protocol == IPPROTO_TCP && desc->relayed_transport_protocol == IPPROTO_TCP)
			{
				turnserver_process_connect_request(transport_protocol, sock, message, saddr, saddr_size, desc);
			}
			else
			{
				turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 400, saddr, saddr_size, desc->key);
			}
			break;
		default:
			return -1;
			break;
		}
	}
	else if (STUN_IS_SUCCESS_RESP(hdr_msg_type) || STUN_IS_ERROR_RESP(hdr_msg_type))
	{
		/* should not happen */
	}
	else if (STUN_IS_INDICATION(hdr_msg_type))
	{
		switch (method)
		{
		case TURN_METHOD_SEND:
			if (desc->relayed_transport_protocol == IPPROTO_UDP)
			{
				turnserver_process_send_indication(message, desc);
			}
			break;
		case TURN_METHOD_DATA:
			/* should not happen */
			return -1;
			break;
		}
	}

	return 0;
}


/**
 * \brief Process a TURN ChannelData.
 * \param transport_protocol transport protocol used
 * \param channel_number channel number
 * \param buf raw data (including ChannelData header)
 * \param buflen length of the data
 * \param remoteaddr source address (TURN client)
 * \param localaddr destination address (TURN server)
 * \param remoteAddrSize sizeof address(TURN client)
 * \param allocation_list list of allocations
 * \return 0 if success, -1 otherwise
 */
int turn_server::turnserver_process_channeldata(int transport_protocol,
	uint16_t channel_number, const char* buf, ssize_t buflen,
	address_type* remoteaddr, address_type* localaddr, int remoteAddrSize, list_head* allocation_list)
{
	struct allocation_desc* desc = NULL;
	struct turn_channel_data* channel_data = NULL;
	struct allocation_channel* alloc_channel = NULL;
	size_t len = 0;
	char* msg = NULL;
	ssize_t nb = -1;
	int optval = 0;
	int save_val = 0;
	socklen_t optlen = sizeof(int);
	struct sockaddr_storage storage;
	uint8_t* peer_addr = NULL;
	uint16_t peer_port = 0;

	debug(DBG_ATTR, "ChannelData received!\n");

	channel_data = (struct turn_channel_data*)buf;
	len = ntohs(channel_data->turn_channel_len);

	if (len > (buflen - sizeof(struct turn_channel_data)))
	{
		/* length mismatch */
		debug(DBG_ATTR, "Length too big\n");
		return -1;
	}

	msg = (char*)channel_data->turn_channel_data;

	if (channel_number > 0x7FFF)
	{
		/* channel reserved for future use */
		debug(DBG_ATTR, "Channel number reserved for future use!\n");
		return -1;
	}

	/* with TCP, length MUST a multiple of four */
	if (transport_protocol == IPPROTO_TCP && (buflen % 4))
	{
		debug(DBG_ATTR, "TCP length must be multiple of four!\n");
		return -1;
	}

	desc = allocation_list_find_tuple(allocation_list, transport_protocol, localaddr, remoteaddr, remoteAddrSize);
	if (!desc)
	{
		/* not found */
		debug(DBG_ATTR, "No allocation found\n");
		return -1;
	}

	if (desc->relayed_transport_protocol != IPPROTO_UDP)
	{
		/* ignore for TCP relayed allocation */
		debug(DBG_ATTR, "ChannelData does not intend to work with TCP relayed address!");
		return -1;
	}

	alloc_channel = allocation_desc_find_channel_number(desc, channel_number);

	if (!alloc_channel)
	{
		/* no channel bound to this peer */
		debug(DBG_ATTR, "No channel bound to this peer\n");
		return -1;
	}

	if (desc->relayed_addr.ss_family != alloc_channel->family)
	{
		debug(DBG_ATTR, "Could not relayed from a different family\n");
		return -1;
	}

	/* check bandwidth limit */
	if (turnserver_check_bandwidth_limit(desc, 0, len))
	{
		debug(DBG_ATTR, "Bandwidth quotas reached!\n");
		return -1;
	}

	peer_addr = alloc_channel->peer_addr;
	peer_port = alloc_channel->peer_port;

	switch (desc->relayed_addr.ss_family)
	{
	case AF_INET:
		((struct sockaddr_in*)&storage)->sin_family = AF_INET;
		memcpy(&((struct sockaddr_in*)&storage)->sin_addr, peer_addr, 4);
		((struct sockaddr_in*)&storage)->sin_port = htons(peer_port);
		memset(&((struct sockaddr_in*)&storage)->sin_zero, 0x00,
			sizeof((struct sockaddr_in*)&storage)->sin_zero);
		break;
	case AF_INET6:
		((struct sockaddr_in6*)&storage)->sin6_family = AF_INET6;
		memcpy(&((struct sockaddr_in6*)&storage)->sin6_addr, peer_addr, 16);
		((struct sockaddr_in6*)&storage)->sin6_port = htons(peer_port);
		((struct sockaddr_in6*)&storage)->sin6_flowinfo = htonl(0);
		((struct sockaddr_in6*)&storage)->sin6_scope_id = htonl(0);
#ifdef SIN6_LEN
		((struct sockaddr_in6*)&storage)->sin6_len = sizeof(struct sockaddr_in6);
#endif
		break;
	default:
		return -1;
		break;
	}

	/* RFC6156: If present, the DONT-FRAGMENT attribute MUST be ignored by the
	 * server for IPv4-IPv6, IPv6-IPv6 and IPv6-IPv4 relays
	 */
	if (desc->relayed_addr.ss_family == AF_INET &&
		(desc->tuple.client_addr.is_v4() == true ||
		(desc->tuple.client_addr.is_v6() == true &&
			IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6*)&desc->tuple.client_addr)->sin6_addr))))
	{
#ifdef OS_SET_DF_SUPPORT
		/* alternate behavior */
		optval = IP_PMTUDISC_DONT;

		if (!getsockopt(desc->relayed_sock, IPPROTO_IP, IP_MTU_DISCOVER, &save_val,
			&optlen))
		{
			setsockopt(desc->relayed_sock, IPPROTO_IP, IP_MTU_DISCOVER, &optval,
				sizeof(int));
		}
		else
		{
			/* little hack for not setting the old value of *_MTU_DISCOVER after
			 * sending message in case getsockopt failed
			 */
			optlen = 0;
		}
#else
		/* avoid compilation warning */
		optval = 0;
		optlen = 0;
		save_val = 0;
#endif
	}

	debug(DBG_ATTR, "Send ChannelData to peer\n");
	nb = sendto(desc->relayed_sock, msg, len, 0, (struct sockaddr*)&storage, sockaddr_get_size(&desc->relayed_addr));

#ifdef OS_SET_DF_SUPPORT
	/* if not an IPv4-IPv4 relay, optlen keep its default value 0 */
	if (optlen)
	{
		/* restore original value */
		setsockopt(desc->relayed_sock, IPPROTO_IP, IP_MTU_DISCOVER, &save_val, sizeof(int));
	}
#endif

	if (nb == -1)
	{
		debug(DBG_ATTR, "turn_send_message failed\n");
	}
	return 0;
	}


/**
 * \brief Check bandwidth limitation on uplink OR downlink.
 * \param desc allocation descriptor
 * \param byteup byte received on uplink connection. 0 means bandwidth check
 * will be made on downlink (if different than 0)
 * \param bytedown byte received on downlink connection. 0 means bandwidth check
 * will be made on uplink (if different than 0)
 * \return 1 if bandwidth threshold is exceeded, 0 otherwise
 */
int turn_server::turnserver_check_bandwidth_limit(allocation_desc* desc, size_t byteup, size_t bytedown)
{
	struct timeval now;
	unsigned long diff = 0;
	unsigned long d = bandwidth;

	if (d <= 0)
	{
		/* bandwidth quota disabled */
		return 0;
	}

	/* check in ms */
	gettimeofday(&now, NULL);

	if (byteup)
	{
		if (desc->bucket_tokenup < desc->bucket_capacity)
		{
			/* count in milliseconds */
			diff = (now.tv_sec - desc->last_timeup.tv_sec) * 1000 + (now.tv_usec - desc->last_timeup.tv_usec) / 1000;
			d *= diff;
			desc->bucket_tokenup = MIN(desc->bucket_capacity, desc->bucket_tokenup + d);
			gettimeofday(&desc->last_timeup, NULL);
		}

		debug(DBG_ATTR, "Tokenup bucket available: %u, tokens requested: %u\n", desc->bucket_tokenup, byteup);

		if (byteup <= desc->bucket_tokenup)
		{
			desc->bucket_tokenup -= byteup;
		}
		else
		{
			/* bandwidth exceeded */
			return 1;
		}
	}
	else if (bytedown)
	{
		if (desc->bucket_tokendown < desc->bucket_capacity)
		{
			/* count in milliseconds */
			diff = (now.tv_sec - desc->last_timedown.tv_sec) * 1000 + (now.tv_usec - desc->last_timedown.tv_usec) / 1000;
			d *= diff;
			desc->bucket_tokendown = MIN(desc->bucket_capacity, desc->bucket_tokendown + d);
			gettimeofday(&desc->last_timedown, NULL);
		}

		debug(DBG_ATTR, "Tokendown bucket available: %u, tokens requested: %u\n", desc->bucket_tokendown, bytedown);

		if (bytedown <= desc->bucket_tokendown)
		{
			desc->bucket_tokendown -= bytedown;
		}
		else
		{
			/* bandwidth exceeded */
			return 1;
		}
	}
	/* bandwidth quota not reached */
	return 0;
}

/**
 * \brief Get sockaddr structure size according to its type.
 * \param ss sockaddr_storage structure
 * \return size of sockaddr_in or sockaddr_in6
 */
socklen_t turn_server::sockaddr_get_size(struct sockaddr_storage* ss)
{
	/* assume address type is IPv4 or IPv6 as TURN specification
	 * supports only these two types of address
	 */
	return (ss->ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
}


/**
 * \brief Process a TURN ChannelBind request.
 * \param transport_protocol transport protocol used
 * \param sock socket
 * \param message TURN message
 * \param saddr source address of the message
 * \param saddr_size sizeof addr
 * \param desc allocation descriptor
 * \param speer TLS peer, if not NULL the connection is in TLS so response is
 * also in TLS
 * \return 0 if success, -1 otherwise
 */
int turn_server::turnserver_process_channelbind_request(int transport_protocol,
	socket_base*  sock, const struct turn_message* message, const address_type* saddr,
	socklen_t saddr_size, struct allocation_desc* desc)
{
	uint16_t hdr_msg_type = htons(message->msg->turn_msg_type);
	uint16_t method = STUN_GET_METHOD(hdr_msg_type);
	struct iovec iov[5]; /* header, lifetime, software, integrity, fingerprint */
	size_t idx = 0;
	struct turn_msg_hdr* hdr = NULL;
	struct turn_attr_hdr* attr = NULL;
	uint16_t channel = 0;
	struct allocation_channel* alloc_channel = NULL;
	struct allocation_permission* alloc_permission = NULL;
	uint8_t family = 0;
	uint16_t peer_port = 0;
	uint8_t peer_addr[16];
	size_t len = 0;
	uint32_t cookie = htonl(STUN_MAGIC_COOKIE);
	uint8_t* p = (uint8_t*)&cookie;
	char str[INET6_ADDRSTRLEN];
	string str2;
	char str3[INET6_ADDRSTRLEN];
	uint16_t port = 0;
	uint16_t port2 = 0;
	uint32_t channel_use = 0; /* if refresh an existing ChannelBind */

	debug(DBG_ATTR, "ChannelBind request received!\n");

	if (!message->channel_number || !message->peer_addr[0])
	{
		/* attributes missing => error 400 */
		debug(DBG_ATTR, "Channel number or peer address attributes missing\n");
		turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 400, saddr, saddr_size, desc->key);
		return 0;
	}

	channel = ntohs(message->channel_number->turn_attr_number);

	if (channel < 0x4000 || channel > 0x7FFF)
	{
		/* bad channel => error 400 */
		debug(DBG_ATTR, "Channel number is invalid\n");
		turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 400, saddr, saddr_size, desc->key);
		return 0;
	}

	switch (message->peer_addr[0]->turn_attr_family)
	{
	case STUN_ATTR_FAMILY_IPV4:
		len = 4;
		family = AF_INET;
		break;
	case STUN_ATTR_FAMILY_IPV6:
		len = 16;
		family = AF_INET6;
		break;
	default:
		return -1;
		break;
	}

	/* check if the client has allocated a family address that match the peer
	 * family address
	 */
	if (desc->relayed_addr.ss_family != family)
	{
		debug(DBG_ATTR, "Do not allow requesting a Channel when allocated address family mismatch peer address family\n");
		turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 443, saddr, saddr_size, desc->key);
		return -1;
	}

	memcpy(peer_addr, message->peer_addr[0]->turn_attr_address, len);
	peer_port = ntohs(message->peer_addr[0]->turn_attr_port);

	if (turn_xor_address_cookie(message->peer_addr[0]->turn_attr_family, peer_addr, &peer_port, p, message->msg->turn_msg_id) == -1)
	{
		return -1;
	}

	inet_ntop(family, peer_addr, str, INET6_ADDRSTRLEN);
	/* check if the address is not blacklisted, also check for an IPv6 tunneled
	 * address that can lead to a tunnel amplification attack (see section 9.1 of
	 * RFC6156)
	 */
	if (turnserver_is_address_denied(peer_addr, len, peer_port) || turnserver_is_ipv6_tunneled_address(peer_addr, len))
	{
		/* permission denied => error 403 */
		debug(DBG_ATTR, "TurnServer does not permit to create a ChannelBind to %s\n", str);
		turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 403, saddr, saddr_size, desc->key);
		return -1;
	}
	debug(DBG_ATTR, "Client request a ChannelBinding for %s %u\n", str, peer_port);
	/* check that the transport address is not currently bound to another
	 * channel
	 */
	channel_use = allocation_desc_find_channel(desc, family, peer_addr, peer_port);
	if (channel_use && channel_use != channel)
	{
		/* transport address already bound to another channel */
		debug(DBG_ATTR, "Transport address already bound to another channel\n");
		turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 400, saddr, saddr_size, desc->key);
		return 0;
	}
	alloc_channel = allocation_desc_find_channel_number(desc, channel);

	if (alloc_channel)
	{
		/* check if same transport address */
		if (alloc_channel->peer_port != peer_port || memcmp(alloc_channel->peer_addr, peer_addr, len) != 0)
		{
			/* different transport address => error 400 */
			debug(DBG_ATTR, "Channel already bound to another transport address\n");
			turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 400, saddr, saddr_size, desc->key);
			return 0;
		}
		/* same transport address OK so refresh */
		allocation_channel_set_timer(alloc_channel, TURN_DEFAULT_CHANNEL_LIFETIME);
	}
	else
	{
		/* allocate new channel */
		if (allocation_desc_add_channel(desc, channel, TURN_DEFAULT_CHANNEL_LIFETIME, family, peer_addr, peer_port) == -1)
		{
			return -1;
		}
	}

	/* get string representation of addresses for syslog */
	if (desc->relayed_addr.ss_family == AF_INET)
	{
		inet_ntop(AF_INET, &((struct sockaddr_in*)&desc->relayed_addr)->sin_addr, str3, INET6_ADDRSTRLEN);
		port = ntohs(((struct sockaddr_in*)&desc->relayed_addr)->sin_port);
	}
	else /* IPv6 */
	{
		inet_ntop(AF_INET6, &((struct sockaddr_in6*)&desc->relayed_addr)->sin6_addr, str3, INET6_ADDRSTRLEN);
		port = ntohs(((struct sockaddr_in6*)&desc->relayed_addr)->sin6_port);
	}


	if (transport_protocol == IPPROTO_TCP)
	{
		auto tcpsocket = (tcp_socket*)sock;
		str2 = tcpsocket->remote_endpoint().address().to_string();
		port2 = tcpsocket->remote_endpoint().port();
	}
	else if (transport_protocol == IPPROTO_UDP)
	{
		auto tcpsocket = (udp_socket*)sock;
		str2 = tcpsocket->remote_endpoint().address().to_string();
		port2 = tcpsocket->remote_endpoint().port();
	}

	//debug(DBG_ATTR, "ChannelBind transport=%u (d)tls=%u source=%s:%u account=%s "
	//	"relayed=%s:%u channel=%s:%u", transport_protocol, desc->relayed_tls ||
	//	desc->relayed_dtls, str2, port2, desc->username, str3, port, str,
	//	peer_port);

	/* find a permission */
	alloc_permission = allocation_desc_find_permission(desc, family, peer_addr);

	/* update or create allocation permission on that peer */
	if (!alloc_permission)
	{
		allocation_desc_add_permission(desc, TURN_DEFAULT_PERMISSION_LIFETIME, family, peer_addr);
	}
	else
	{
		allocation_permission_set_timer(alloc_permission, TURN_DEFAULT_PERMISSION_LIFETIME);
	}

	/* finally send the response */
	if (!(hdr = turn_msg_channelbind_response_create(0, message->msg->turn_msg_id,
		&iov[idx])))
	{
		turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 500, saddr, saddr_size, desc->key);
		return -1;
	}
	idx++;

	/* software (not fatal if it cannot be allocated) */
	if ((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION,
		sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
	{
		hdr->turn_msg_len += iov[idx].iov_len;
		idx++;
	}

	if (turn_add_message_integrity(iov, &idx, desc->key, sizeof(desc->key), 1)
		== -1)
	{
		iovec_free_data(iov, idx);
		turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 500, saddr, saddr_size, desc->key);
		return -1;
	}

	debug(DBG_ATTR, "ChannelBind successful, send success ChannelBind response\n");

	/* finally send the response */
	if (turn_send_message(transport_protocol, sock, saddr, saddr_size, ntohs(hdr->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, idx) == -1)
	{
		debug(DBG_ATTR, "turn_send_message failed\n");
	}

	iovec_free_data(iov, idx);
	return 0;
}


/**
 * \brief Process a TURN Send indication.
 * \param message TURN message
 * \param desc allocation descriptor
 * \return 0 if success, -1 otherwise
 */
int turn_server::turnserver_process_send_indication(const struct turn_message* message, struct allocation_desc* desc)
{
	const char* msg = NULL;
	size_t msg_len = 0;
	struct allocation_permission* alloc_permission = NULL;
	uint16_t peer_port = 0;
	uint8_t peer_addr[16];
	size_t len = 0;
	uint32_t cookie = htonl(STUN_MAGIC_COOKIE);
	uint8_t* p = (uint8_t*)&cookie;
	ssize_t nb = -1;
	/* for get/setsockopt */
	int optval = 0;
	int save_val = 0;
	socklen_t optlen = sizeof(int);
	char str[INET6_ADDRSTRLEN];
	int family = 0;
	struct sockaddr_storage storage;

	debug(DBG_ATTR, "Send indication received!\n");

	if (!message->peer_addr[0] || !message->data)
	{
		/* no peer address, indication ignored */
		debug(DBG_ATTR, "No peer address\n");
		return -1;
	}

	switch (message->peer_addr[0]->turn_attr_family)
	{
	case STUN_ATTR_FAMILY_IPV4:
		len = 4;
		family = AF_INET;
		break;
	case STUN_ATTR_FAMILY_IPV6:
		len = 16;
		family = AF_INET6;
		break;
	default:
		return -1;
		break;
	}

	if (desc->relayed_addr.ss_family != family)
	{
		debug(DBG_ATTR, "Could not relayed from a different family\n");
		return -1;
	}

	/* copy peer address */
	memcpy(peer_addr, message->peer_addr[0]->turn_attr_address, len);
	peer_port = ntohs(message->peer_addr[0]->turn_attr_port);

	if (turn_xor_address_cookie(message->peer_addr[0]->turn_attr_family, peer_addr,
		&peer_port, p, message->msg->turn_msg_id) == -1)
	{
		return -1;
	}

	/* check if the address is not blacklisted, also check for an IPv6 tunneled
	 * address that can lead to a tunnel amplification attack (see section 9.1 of
	 * RFC6156)
	 */
	if (turnserver_is_address_denied(peer_addr, len, peer_port) ||
		turnserver_is_ipv6_tunneled_address(peer_addr, len))
	{
		inet_ntop(family, peer_addr, str, INET6_ADDRSTRLEN);
		debug(DBG_ATTR, "TurnServer does not permit relaying to %s\n", str);
		return -1;
	}

	/* find a permission */
	alloc_permission = allocation_desc_find_permission(desc,
		desc->relayed_addr.ss_family, peer_addr);

	if (!alloc_permission)
	{
		/* no permission so packet dropped! */
		inet_ntop(family, peer_addr, str, INET6_ADDRSTRLEN);
		debug(DBG_ATTR, "No permission for this peer (%s)\n", str);
		return -1;
	}

	/* send the message */
	if (message->data)
	{
		msg = (char*)message->data->turn_attr_data;
		msg_len = ntohs(message->data->turn_attr_len);

		/* check bandwidth limit */
		if (turnserver_check_bandwidth_limit(desc, 0, msg_len))
		{
			debug(DBG_ATTR, "Bandwidth quotas reached!\n");
			return -1;
		}

		switch (desc->relayed_addr.ss_family)
		{
		case AF_INET:
			((struct sockaddr_in*)&storage)->sin_family = AF_INET;
			memcpy(&((struct sockaddr_in*)&storage)->sin_addr, peer_addr, 4);
			((struct sockaddr_in*)&storage)->sin_port = htons(peer_port);
			memset(&((struct sockaddr_in*)&storage)->sin_zero, 0x00,
				sizeof((struct sockaddr_in*)&storage)->sin_zero);
			break;
		case AF_INET6:
			((struct sockaddr_in6*)&storage)->sin6_family = AF_INET6;
			memcpy(&((struct sockaddr_in6*)&storage)->sin6_addr, peer_addr, 16);
			((struct sockaddr_in6*)&storage)->sin6_port = htons(peer_port);
			((struct sockaddr_in6*)&storage)->sin6_flowinfo = htonl(0);
			((struct sockaddr_in6*)&storage)->sin6_scope_id = htonl(0);
#ifdef SIN6_LEN
			((struct sockaddr_in6*)&storage)->sin6_len =
				sizeof(struct sockaddr_in6);
#endif
			break;
		default:
			return -1;
			break;
	}

		/* RFC6156: If present, the DONT-FRAGMENT attribute MUST be ignored by the
		 * server for IPv4-IPv6, IPv6-IPv6 and IPv6-IPv4 relays
		 */
		if (desc->relayed_addr.ss_family == AF_INET && (desc->tuple.client_addr.is_v4() || (desc->tuple.client_addr.is_v6())))
		{
			/* following is for IPv4-IPv4 relay only */
#ifdef OS_SET_DF_SUPPORT
			if (message->dont_fragment)
			{
				optval = IP_PMTUDISC_DO;
				debug(DBG_ATTR, "Will set DF flag\n");
			}
			else /* IPv4-IPv4 relay but no DONT-FRAGMENT attribute */
			{
				/* alternate behavior, set DF to 0 */
				optval = IP_PMTUDISC_DONT;
				debug(DBG_ATTR, "Will not set DF flag\n");
			}

			if (!getsockopt(desc->relayed_sock, IPPROTO_IP, IP_MTU_DISCOVER, &save_val,
				&optlen))
			{
				setsockopt(desc->relayed_sock, IPPROTO_IP, IP_MTU_DISCOVER, &optval,
					sizeof(int));
			}
			else
			{
				/* little hack for not setting the old value of *_MTU_DISCOVER after
				 * sending message in case getsockopt failed
				 */
				optlen = 0;
			}
#else
	  /* avoid compilation warning */
			optval = 0;
			optlen = 0;
			save_val = 0;

			if (message->dont_fragment)
			{
				/* ignore message */
				debug(DBG_ATTR, "DONT-FRAGMENT attribute present and OS cannot set DF flag, ignore packet!\n");
				return -1;
			}
#endif
		}

		debug(DBG_ATTR, "Send data to peer\n");
		nb = sendto(desc->relayed_sock, msg, msg_len, 0, (struct sockaddr*)&storage,
			sockaddr_get_size(&desc->relayed_addr));

		/* if not an IPv4-IPv4 relay, optlen keep its default value 0 */
#ifdef OS_SET_DF_SUPPORT
		if (optlen)
		{
			/* restore original value */
			setsockopt(desc->relayed_sock, IPPROTO_IP, IP_MTU_DISCOVER, &save_val,
				sizeof(int));
		}
#endif

		if (nb == -1)
		{
			debug(DBG_ATTR, "turn_send_message failed\n");
		}
}

	return 0;
}


/**
 * \brief Verify if address/port is in denied list.
 * \param addr IPv4/IPv6 address to check
 * \param addrlen sizeof the address (IPv4 = 4, IPv6 = 16)
 * \param port port to check
 * \return 1 if address is denied, 0 otherwise
 */
int  turn_server::turnserver_is_address_denied(const uint8_t* addr, size_t addrlen, uint16_t port)
{
	struct list_head* get = NULL;
	struct list_head* n = NULL;
	uint8_t nb = 0;
	uint8_t mod = 0;
	size_t i = 0;

	/* IPv6 address maximum length is 16 bytes */
	if (addrlen > 16)
	{
		return 0;
	}

	list_iterate_safe(get, n, &g_denied_address_list)
	{
		struct denied_address* tmp = list_get(get, struct denied_address, list);
		int diff = 0;

		/* compare addresses from same family */
		if ((tmp->family == AF_INET6 && addrlen != 16) ||
			(tmp->family == AF_INET && addrlen != 4))
		{
			continue;
		}

		nb = (uint8_t)(tmp->mask / 8);

		for (i = 0; i < nb; i++)
		{
			if (tmp->addr[i] != addr[i])
			{
				diff = 1;
				break;
			}
		}

		/* if mismatch in the addresses */
		if (diff)
		{
			continue;
		}

		/* OK so now the full bytes from the address are the same,
		 * check for last bit if any
		 */
		mod = (tmp->mask % 8);

		if (mod)
		{
			uint8_t b = 0;

			for (i = 0; i < mod; i++)
			{
				b |= (1 << (7 - i));
			}

			if ((tmp->addr[nb] & b) == (addr[nb] & b))
			{
				if (tmp->port == 0 || tmp->port == port)
				{
					return 1;
				}
			}
		}
		else
		{
			if (tmp->port == 0 || tmp->port == port)
			{
				return 1;
			}
		}
	}
	return 0;
}

/**
 * \brief Verify if the address is an IPv6 tunneled ones.
 * \param addr address to check
 * \param addrlen sizeof address
 * \return 1 if address is an IPv6 tunneled ones, 0 otherwise
 */
int  turn_server::turnserver_is_ipv6_tunneled_address(const uint8_t* addr, size_t addrlen)
{
	if (addrlen == 16)
	{
		static const uint8_t addr_6to4[2] = { 0x20, 0x02 };
		static const uint8_t addr_teredo[4] = { 0x20, 0x01, 0x00, 0x00 };

		/* 6to4 or teredo address ? */
		if (!memcmp(addr, addr_6to4, 2) || !memcmp(addr, addr_teredo, 4))
		{
			return 1;
		}
	}
	return 0;
}


/**
 * \brief Process a TURN Connect request (RFC6062).
 * \param transport_protocol transport protocol used
 * \param sock socket
 * \param message STUN message
 * \param saddr source address
 * \param saddr_size sizeof address
 * \param desc allocation descriptor
 * \param speer TLS peer, if not NULL the connection is in TLS so response is
 * also in TLS
 * \return 0 if success, -1 otherwise
 */
int  turn_server::turnserver_process_connect_request(int transport_protocol, socket_base* sock,
	const struct turn_message* message, const address_type* saddr,
	socklen_t saddr_size, struct allocation_desc* desc)
{
	uint16_t hdr_msg_type = htons(message->msg->turn_msg_type);
	uint16_t method = STUN_GET_METHOD(hdr_msg_type);
	uint8_t peer_addr[16];
	uint16_t peer_port = 0;
	uint16_t len = 0;
	struct sockaddr_storage storage;
	int peer_sock = -1;
	int family = 0;
	uint32_t cookie = htonl(STUN_MAGIC_COOKIE);
	uint8_t* p = (uint8_t*)&cookie;
	uint32_t id = 0;
	long flags = 0;
	int ret = 0;

	debug(DBG_ATTR, "Connect request received!\n");

	/* check also that allocation has a maximum of one
	 * outgoing connection
	 * (if relayed_sock_tcp equals -1 it means that it exists
	 * already an outgoing connection for this allocation)
	 */
	if (!message->peer_addr[0] || desc->relayed_sock_tcp == -1)
	{
		turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 400, saddr, saddr_size, desc->key);
		return -1;
	}

	switch (message->peer_addr[0]->turn_attr_family)
	{
	case STUN_ATTR_FAMILY_IPV4:
		len = 4;
		family = AF_INET;
		break;
	case STUN_ATTR_FAMILY_IPV6:
		len = 16;
		family = AF_INET6;
		break;
	default:
		return -1;
		break;
	}

	/* copy address/port */
	memcpy(peer_addr, message->peer_addr[0]->turn_attr_address, len);
	peer_port = ntohs(message->peer_addr[0]->turn_attr_port);

	if (turn_xor_address_cookie(family, peer_addr, &peer_port, p,
		message->msg->turn_msg_id) == -1)
	{
		return -1;
	}

	if (desc->relayed_addr.ss_family != family)
	{
		debug(DBG_ATTR, "Could not relayed from a different family\n");
		turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 400, saddr, saddr_size, desc->key);
		return -1;
	}

	/* check if server has already processed the same
	 * XOR-PEER-ADDRESS with this allocation => error 446
	 */
	if (allocation_desc_find_tcp_relay_addr(desc, family, peer_addr, peer_port))
	{
		turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 446, saddr, saddr_size, desc->key);
		return -1;
	}

	/* check if the address is not blacklisted, also check for an IPv6 tunneled
	 * address that can lead to a tunne amplification attack
	 * (see section 9.1 of RFC6156)
	 */
	if (turnserver_is_address_denied(peer_addr, len, peer_port) ||
		turnserver_is_ipv6_tunneled_address(peer_addr, len))
	{
		turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 403, saddr, saddr_size, desc->key);
		return -1;
	}

	/* connection to peer */
	switch (family)
	{
	case AF_INET:
		((struct sockaddr_in*)&storage)->sin_family = AF_INET;
		memcpy(&((struct sockaddr_in*)&storage)->sin_addr, peer_addr, 4);
		((struct sockaddr_in*)&storage)->sin_port = htons(peer_port);
		memset(&((struct sockaddr_in*)&storage)->sin_zero, 0x00,
			sizeof((struct sockaddr_in*)&storage)->sin_zero);
		break;
	case AF_INET6:
		((struct sockaddr_in6*)&storage)->sin6_family = AF_INET6;
		memcpy(&((struct sockaddr_in6*)&storage)->sin6_addr, peer_addr, 16);
		((struct sockaddr_in6*)&storage)->sin6_port = htons(peer_port);
		((struct sockaddr_in6*)&storage)->sin6_flowinfo = htonl(0);
		((struct sockaddr_in6*)&storage)->sin6_scope_id = htonl(0);
#ifdef SIN6_LEN
		((struct sockaddr_in6*)&storage)->sin6_len = sizeof(struct sockaddr_in6);
#endif
		break;
	default:
		return -1;
		break;
	}

	peer_sock = desc->relayed_sock_tcp;
	desc->relayed_sock_tcp = -1;

	/* set non-blocking mode */
	if ((flags = fcntl(peer_sock, F_GETFL, NULL)) == -1)
	{
		return -1;
	}

	flags |= O_NONBLOCK;

	if (fcntl(peer_sock, F_SETFL, flags) == -1)
	{
		return -1;
	}

	ret = connect(peer_sock, (struct sockaddr*)&storage, sockaddr_get_size(&storage));

	if (errno == EINPROGRESS)
	{
		/* connection ongoing */
		/* generate unique ID */
		random_bytes_generate((uint8_t*)&id, 4);
		/* add it to allocation */
		if (allocation_desc_add_tcp_relay(desc, id, peer_sock, family, peer_addr, peer_port, TURN_DEFAULT_TCP_RELAY_TIMEOUT, 0, message->msg->turn_msg_id) == -1)
		{
			turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 500, saddr, saddr_size, desc->key);
			return -1;
		}
		return 0;
	}
	else if (ret < 0)
	{
		/* error */
		char error_str[256];
		//get_error(errno, error_str, sizeof(error_str));
		debug(DBG_ATTR, "connect to peer failed: %s", error_str);
		turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 447, saddr, saddr_size, desc->key);
		return -1;
	}

	return -1;
	}


/**
 * \brief Process a STUN Binding request.
 * \param transport_protocol transport protocol used
 * \param sock socket
 * \param message STUN message
 * \param saddr source address
 * \param saddr_size sizeof address
 * \param speer TLS peer, if not NULL the connection is in TLS so response is
 * also in TLS
 * \return 0 if success, -1 otherwise
 */
int turn_server::turnserver_process_binding_request(int transport_protocol, socket_base* sock,
	const struct turn_message* message, const address_type* saddr,
	socklen_t saddr_size)
{
	iovec iov[4]; /* header, software, xor-address, fingerprint */
	size_t idx = 0;
	struct turn_msg_hdr* hdr = NULL;
	struct turn_attr_hdr* attr = NULL;

	debug(DBG_ATTR, "Binding request received!\n");

	if (!(hdr = turn_msg_binding_response_create(0, message->msg->turn_msg_id, &iov[idx])))
	{
		return -1;
	}
	idx++;

	if (!(attr = turn_attr_xor_mapped_address_create(sock, transport_protocol, STUN_MAGIC_COOKIE, message->msg->turn_msg_id, &iov[idx])))
	{
		iovec_free_data(iov, idx);
		turnserver_send_error(transport_protocol, sock, STUN_METHOD_BINDING, message->msg->turn_msg_id, 500, saddr, saddr_size, NULL);
		return -1;
	}
	hdr->turn_msg_len += iov[idx].iov_len;
	idx++;

	/* software (not fatal if it cannot be allocated) */
	if ((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION,
		sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
	{
		hdr->turn_msg_len += iov[idx].iov_len;
		idx++;
	}

	/* NOTE: maybe add a configuration flag to enable/disable fingerprint in
	 * output message
	 */
	 /* add a fingerprint */
	if (!(attr = turn_attr_fingerprint_create(0, &iov[idx])))
	{
		iovec_free_data(iov, idx);
		turnserver_send_error(transport_protocol, sock, STUN_METHOD_BINDING, message->msg->turn_msg_id, 500, saddr, saddr_size, NULL);
		return -1;
	}
	hdr->turn_msg_len += iov[idx].iov_len;
	idx++;

	/* compute fingerprint */

	/* convert to big endian */
	hdr->turn_msg_len = htons(hdr->turn_msg_len);

	/* do not take into account the attribute itself */
	((struct turn_attr_fingerprint*)attr)->turn_attr_crc =
		htonl(turn_calculate_fingerprint(iov, idx - 1));
	((struct turn_attr_fingerprint*)attr)->turn_attr_crc ^=
		htonl(STUN_FINGERPRINT_XOR_VALUE);


	if (turn_send_message(transport_protocol, sock, saddr, (int)saddr_size, (size_t)(ntohs(hdr->turn_msg_len) + sizeof(struct turn_msg_hdr)), iov, idx) == -1)
	{
		debug(DBG_ATTR, "turn_send_message failed\n");
	}

	iovec_free_data(iov, idx);
	return 0;
}
/**
 * \brief Process a TURN ConnectionBind request (RFC6062).
 * \param transport_protocol transport protocol used
 * \param sock socket
 * \param message STUN message
 * \param saddr source address
 * \param saddr_size sizeof address
 * \param speer TLS peer, if not NULL the connection is in TLS so response is
 * also in TLS
 * \param account account descriptor
 * \param allocation_list list of allocations
 * \return 0 if success, -1 otherwise
 */
int  turn_server::turnserver_process_connectionbind_request(int transport_protocol,
	socket_base* sock, const struct turn_message* message, const address_type* saddr,
	socklen_t saddr_size, struct account_desc* account,
	struct list_head* allocation_list)
{
	uint16_t hdr_msg_type = htons(message->msg->turn_msg_type);
	uint16_t method = STUN_GET_METHOD(hdr_msg_type);
	struct allocation_tcp_relay* tcp_relay = NULL;
	struct list_head* get = NULL;
	struct list_head* n = NULL;
	struct allocation_desc* desc = NULL;
	struct turn_msg_hdr* hdr = NULL;
	struct turn_attr_hdr* attr = NULL;
	struct iovec iov[8];
	size_t idx = 0;

	debug(DBG_ATTR, "ConnectionBind request received!\n");

	if (!message->connection_id)
	{
		debug(DBG_ATTR, "No CONNECTION-ID attribute!\n");
		turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 400, saddr, saddr_size, account->key);
		return -1;
	}

	/* find corresponding allocation for TCP connection ID */
	list_iterate_safe(get, n, allocation_list)
	{
		struct allocation_desc* tmp = list_get(get, struct allocation_desc, list);
		struct list_head* get2 = NULL;
		struct list_head* n2 = NULL;

		if (tmp->relayed_transport_protocol != IPPROTO_TCP || memcmp(tmp->key, account->key, sizeof(tmp->key) != 0))
		{
			continue;
		}

		list_iterate_safe(get2, n2, &tmp->tcp_relays)
		{
			struct allocation_tcp_relay* tmp2 =
				list_get(get2, struct allocation_tcp_relay, list);

			if (tmp2->connection_id == message->connection_id->turn_attr_id)
			{
				desc = tmp;
				break;
			}
		}

		/* found ? */
		if (desc)
		{
			break;
		}
	}

	/* check if allocation exists and if its ID exists for this allocation
	 * otherwise => error 400
	 */
	if (!desc || !(tcp_relay = allocation_desc_find_tcp_relay_id(desc, message->connection_id->turn_attr_id)))
	{
		debug(DBG_ATTR, "No allocation or no allocation for CONNECTION-ID\n");
		turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 400, saddr, saddr_size, account->key);
		return -1;
	}

	/* only one ConnectionBind for a connection ID */
	if (tcp_relay->client_sock != NULL)
	{
		return 0;
	}

	/* ConnectionBind response */
	if (!(hdr = turn_msg_connectionbind_response_create(0, message->msg->turn_msg_id, &iov[idx])))
	{
		turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 500, saddr, saddr_size, account->key);
		return -1;
	}
	idx++;

	/* connection-id */
	if (!(attr = turn_attr_connection_id_create(message->connection_id->turn_attr_id, &iov[idx])))
	{
		iovec_free_data(iov, idx);
		turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 500, saddr, saddr_size, account->key);
		return -1;
	}
	hdr->turn_msg_len += iov[idx].iov_len;
	idx++;

	/* software (not fatal if it cannot be allocated) */
	if ((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION,
		strlen(SOFTWARE_DESCRIPTION), &iov[idx])))
	{
		hdr->turn_msg_len += iov[idx].iov_len;
		idx++;
	}

	if (turn_add_message_integrity(iov, &idx, desc->key, sizeof(desc->key), 1)
		== -1)
	{
		/* MESSAGE-INTEGRITY option has to be in message, so
		 * deallocate ressources and return
		 */
		iovec_free_data(iov, idx);
		turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 500, saddr, saddr_size, account->key);
		return -1;
	}

	if (turn_send_message(transport_protocol, sock, saddr, saddr_size, ntohs(hdr->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, idx) == -1)
	{
		debug(DBG_ATTR, "turn_send_message failed\n");
		iovec_free_data(iov, idx);
		return -1;
	}

	/* free message */
	iovec_free_data(iov, idx);

	/* initialized client socket */
	tcp_relay->client_sock = sock;

	/* now on this socket no other TURN messaging is allowed, remove the socket
	 * from the TCP remote sockets list
	 */
	list_iterate_safe(get, n, &g_tcp_socket_list)
	{
		struct socket_desc* tmp = list_get(get, struct socket_desc, list);

		if (tmp->sock == sock)
		{
			tmp->sock = NULL;
			break;
		}
	}

	/* when removed from tcp_socket_list, it will be checked
	 * again in tcp_relay list in select() so avoid it
	 */
	tcp_relay->newConnection = 1;

	/* stop timer */
	allocation_tcp_relay_set_timer(tcp_relay, 0);

	/* send out buffered data
	 * note that it is only used if server
	 * has been configured to use userspace
	 * TCP internal buffer
	 */
	if (tcp_relay->buf_len)
	{
		ssize_t nb_read = 0;
		ssize_t nb_read2 = 0;

		debug(DBG_ATTR, "Send buffered data to client (TURN-TCP)\n");

		/* server has buffered data available,
	 * send them to client
	 */
		if (transport_protocol == IPPROTO_UDP)
		{
			manager.udp_send(tcp_relay->buf, (udp_socket*)sock);
		}
		else {
			manager.tcp_send(tcp_relay->buf, (tcp_socket*)sock);
		}
		tcp_relay->buf_len = 0;


	}

	/* free memory now as it will not be used anymore */
	if (tcp_relay->buf)
	{
		free(tcp_relay->buf);
		tcp_relay->buf = NULL;
		tcp_relay->buf_size = 0;
	}

	return 0;
}


/**
 * \brief Process a TURN Allocate request.
 * \param transport_protocol transport protocol used
 * \param sock socket
 * \param message TURN message
 * \param saddr source address of the message
 * \param daddr destination address of the message
 * \param saddr_size sizeof addr
 * \param allocation_list list of allocations
 * \param account account descriptor
 * \param speer TLS peer, if not NULL the connection is in TLS so response is
 * also in TLS
 * \return 0 if success, -1 otherwise
 */
int  turn_server::turnserver_process_allocate_request(int transport_protocol, socket_base* sock,
	const struct turn_message* message, const address_type* saddr,
	const address_type* daddr, socklen_t saddr_size, struct account_desc* account)
{
	struct allocation_desc* desc = NULL;
	struct itimerspec t; /* time before expire */
	uint16_t hdr_msg_type = ntohs(message->msg->turn_msg_type);
	uint16_t method = STUN_GET_METHOD(hdr_msg_type);
	struct sockaddr_storage relayed_addr;
	int r_flag = 0;
	uint32_t lifetime = 0;
	uint16_t port = 0;
	uint16_t reservation_port = 0;
	int relayed_sock = -1;
	int relayed_sock_tcp = -1; /* RFC6062 (TURN-TCP) */
	int reservation_sock = -1;
	socklen_t relayed_size = sizeof(struct sockaddr_storage);
	size_t quit_loop = 0;
	uint8_t reservation_token[8];
	char str[INET6_ADDRSTRLEN];
	string str2;
	uint16_t port2 = 0;
	int has_token = 0;
	char* family_address = NULL;
	const uint16_t max_port = 65535;
	const uint16_t min_port = 49152;

	debug(DBG_ATTR, "Allocate request received!\n");

	/* check if it was a valid allocation */
	desc = allocation_list_find_tuple(_allocation_list, transport_protocol, daddr, saddr, saddr_size);

	if (desc)
	{
		if (transport_protocol == IPPROTO_UDP && !memcmp(message->msg->turn_msg_id,
			desc->transaction_id, 12))
		{
			/* the request is a retransmission of a valid request, rebuild the
			 * response
			 */

			 /* get some states */
			timer_gettime(desc->expire_timer, &t);
			lifetime = t.it_value.tv_sec;
			memcpy(&relayed_addr, &desc->relayed_addr, sizeof(struct sockaddr_storage));
			/* goto is bad... */
			goto send_success_response;
		}
		else
		{
			/* allocation mismatch => error 437 */
			turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 437, saddr, saddr_size, desc->key);
		}

		return 0;
	}

	str2 = saddr->to_string();
	/* get string representation of address for syslog */
	if (transport_protocol == IPPROTO_UDP)
	{
		port2 = ((udp_socket*)sock)->remote_endpoint().port();
	}
	else /* IPv6 */
	{
		port2 = ((tcp_socket*)sock)->remote_endpoint().port();

	}

	/* check for allocation quota */
	if (account->allocations >= max_relay_per_username)
	{
		/* quota exceeded => error 486 */
		//debug(DBG_ATTR, "Allocation transport=%u (d)tls=%u source=%s:%u account=%s quota exceeded", transport_protocol, 0, str2, port2, account->username);
		turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 486, saddr, saddr_size, account->key);
		return -1;
	}

	/* check requested-transport */
	if (!message->requested_transport)
	{
		/* bad request => error 400 */
		turnserver_send_error(transport_protocol, sock, method,
			message->msg->turn_msg_id, 400, saddr, saddr_size, account->key);
		return 0;
	}

	/* check if DONT-FRAGMENT attribute is supported */
#ifndef OS_SET_DF_SUPPORT
	if (message->dont_fragment)
	{
		/* header, error-code, unknown-attributes, software, message-integrity,
		 * fingerprint
		 */
		struct iovec iov[6];
		uint16_t unknown[2];
		struct turn_msg_hdr* error = NULL;
		struct turn_attr_hdr* attr = NULL;
		size_t idx = 0;

		/* send error 420 */
		unknown[0] = TURN_ATTR_DONT_FRAGMENT;

		if (!(error = turn_error_response_420(method, message->msg->turn_msg_id, unknown, 1, iov, &idx)))
		{
			turnserver_send_error(transport_protocol, sock, method,
				message->msg->turn_msg_id, 500, saddr, saddr_size,
				account->key);
			return -1;
		}

		/* software (not fatal if it cannot be allocated) */
		if ((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION,
			sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
		{
			error->turn_msg_len += iov[idx].iov_len;
			idx++;
		}

		if (turn_add_message_integrity(iov, &idx, desc->key, sizeof(desc->key), 1) == -1)
		{
			iovec_free_data(iov, idx);
			turnserver_send_error(transport_protocol, sock, method,
				message->msg->turn_msg_id, 500, saddr, saddr_size,
				account->key);
			return -1;
		}

		if (turn_send_message(transport_protocol, sock, saddr, saddr_size, ntohs(error->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, idx) == -1)
		{
			debug(DBG_ATTR, "turn_send_message failed\n");
		}

		/* free sent data */
		iovec_free_data(iov, idx);
		return 0;
	}
#endif

	/* check if server supports requested transport */
	if (message->requested_transport->turn_attr_protocol != IPPROTO_UDP &&
		(message->requested_transport->turn_attr_protocol != IPPROTO_TCP || !is_turn_tcp))
	{
		/* unsupported transport protocol => error 442 */
		turnserver_send_error(transport_protocol, sock, method, message->msg->turn_msg_id, 442, saddr, saddr_size, account->key);
		return 0;
	}

	if (message->requested_transport->turn_attr_protocol == IPPROTO_TCP)
	{
		/* RFC6062 (TURN-TCP):
		 * - do not permit to allocate TCP relay with an
		 * UDP-based connection
		 * - requests do not contains DONT-FRAGMENT,
		 * RESERVATION-TOKEN or EVEN-PORT.
		 * => error 400
		 */
		if (transport_protocol == IPPROTO_UDP || message->dont_fragment ||
			message->reservation_token || message->even_port)
		{
			turnserver_send_error(transport_protocol, sock, method,
				message->msg->turn_msg_id, 400, saddr, saddr_size,
				account->key);
			return 0;
		}
	}

	if (message->even_port && message->reservation_token)
	{
		/* cannot have both EVEN-PORT and RESERVATION-TOKEN => error 400 */
		turnserver_send_error(transport_protocol, sock, method,
			message->msg->turn_msg_id, 400, saddr, saddr_size, account->key);
		return 0;
	}

	if (message->requested_addr_family && message->reservation_token)
	{
		/* RFC6156: cannot have both REQUESTED-ADDRESS-FAMILY and RESERVATION-TOKEN
		 * => error 400
		 */
		turnserver_send_error(transport_protocol, sock, method,
			message->msg->turn_msg_id, 400, saddr, saddr_size, account->key);
		return 0;
	}

	/* check reservation-token */
	if (message->reservation_token)
	{
		struct allocation_token* token = NULL;

		/* check if the requested reservation-token exists */
		if ((token = allocation_token_list_find(&g_token_list, message->reservation_token->turn_attr_token)))
		{
			relayed_sock = token->sock;
			has_token = 1;

			/* suppress from the list */
			turnserver_block_realtime_signal();
			allocation_token_set_timer(token, 0); /* stop timer */
			LIST_DEL(&token->list2);
			turnserver_unblock_realtime_signal();

			allocation_token_list_remove(&g_token_list, token);
			debug(DBG_ATTR, "Take token reserved address!\n");
		}
		else
		{
			/* token does not exists so token not valid => error 508 */
			turnserver_send_error(transport_protocol, sock, method,
				message->msg->turn_msg_id, 508, saddr, saddr_size,
				account->key);
			return 0;
		}
	}

	if (message->even_port)
	{
		r_flag = message->even_port->turn_attr_flags & 0x80;

		/* check if there are unknown other flags */
		if (message->even_port->turn_attr_flags & (~g_supported_even_port_flags))
		{
			/* unsupported flags => error 508 */
			turnserver_send_error(transport_protocol, sock, method,
				message->msg->turn_msg_id, 508, saddr, saddr_size,
				account->key);
			return 0;
		}
	}

	if (message->lifetime)
	{
		lifetime = htonl(message->lifetime->turn_attr_lifetime);

		debug(DBG_ATTR, "lifetime: %u seconds\n", lifetime);

		/* adjust lifetime (cannot be greater than maximum allowed) */
		lifetime = MIN(lifetime, TURN_MAX_ALLOCATION_LIFETIME);

		/* lifetime cannot be smaller than default */
		lifetime = MAX(lifetime, TURN_DEFAULT_ALLOCATION_LIFETIME);
	}
	else
	{
		/* cannot override default max value for allocation time */
		lifetime = MIN(allocation_lifetime, TURN_MAX_ALLOCATION_LIFETIME);
	}

	/* RFC6156 */
	if (message->requested_addr_family)
	{
		switch (message->requested_addr_family->turn_attr_family)
		{
		case STUN_ATTR_FAMILY_IPV4:
			family_address = listen_address;
			break;
		case STUN_ATTR_FAMILY_IPV6:
			family_address = listen_address;
			break;
		default:
			family_address = NULL;
			break;
		}

		/* check the family requested is supported */
		if (!family_address)
		{
			/* family not supported */
			turnserver_send_error(transport_protocol, sock, method,
				message->msg->turn_msg_id, 440, saddr, saddr_size,
				account->key);
			return -1;
		}
	}
	else
	{
		/* REQUESTED-ADDRESS-FAMILY absent so allocate an IPv4 address */
		family_address = listen_address;

		if (!family_address)
		{
			/* only happen when IPv4 relaying is disabled and try to allocate IPv6
			 * address without adding REQUESTED-ADDRESS-FAMILY attribute.
			 */
			 /* family not supported */
			turnserver_send_error(transport_protocol, sock, method,
				message->msg->turn_msg_id, 440, saddr, saddr_size,
				account->key);
			return -1;
		}
	}

	strncpy(str, family_address, INET6_ADDRSTRLEN);
	str[INET6_ADDRSTRLEN - 1] = 0x00;

	/* after all these checks, allocate an allocation! */

	/* allocate the relayed address or skip this if server has a token,
	 * try 5 times to find a free port or couple of free ports.
	 */
	while (!has_token && (relayed_sock == -1 && quit_loop < 5))
	{
		/* pick up a port (default between 49152 - 65535) */
		port = (uint16_t)(rand() % (max_port - min_port)) + min_port;

		/* allocate a even port */
		if (message->even_port && (port % 2))
		{
			port++;
		}

		/* TCP or UDP */
		/* in case of TCP, allow socket to reuse transport address since we create
		 * another socket that will be bound to the same address
		 */
		relayed_sock = socket_create(
			(protocol_type)message->requested_transport->turn_attr_protocol, str, port,
			(int)message->requested_transport->turn_attr_protocol == IPPROTO_TCP,
			(int)message->requested_transport->turn_attr_protocol == IPPROTO_TCP);

		if (relayed_sock == -1)
		{
			quit_loop++;
			continue;
		}

		if (message->requested_transport->turn_attr_protocol == IPPROTO_TCP)
		{
			/* special handling for TCP relay:
			 * create a second socket bind on the same address/port,
			 * the first one will be used to listen incoming connections,
			 * the second will be used to connect peer (Connect request)
			 */
			relayed_sock_tcp = socket_create((protocol_type)message->requested_transport->turn_attr_protocol, str, port, 1, 1);

			if (relayed_sock_tcp == -1)
			{
				/* system error */

				close(relayed_sock);
				turnserver_send_error(transport_protocol, sock, method,
					message->msg->turn_msg_id, 500, saddr, saddr_size,
					account->key);
				return -1;
			}

			if (listen(relayed_sock, 5) == -1)
			{
				/* system error */

				close(relayed_sock);
				close(relayed_sock_tcp);
				turnserver_send_error(transport_protocol, sock, method,
					message->msg->turn_msg_id, 500, saddr, saddr_size,
					account->key);
				return -1;
			}
		}

		if (r_flag)
		{
			reservation_port = port + 1;
			reservation_sock = socket_create((protocol_type)IPPROTO_UDP, str, reservation_port, 0, 0);

			if (reservation_sock == -1)
			{
				close(relayed_sock);
				relayed_sock = -1;
			}
			else
			{
				struct allocation_token* token = NULL;

				/* store the reservation */
				random_bytes_generate(reservation_token, 8);

				token = allocation_token_new(reservation_token, reservation_sock, TURN_DEFAULT_TOKEN_LIFETIME);
				if (token)
				{
					allocation_token_list_add(&g_token_list, token);
				}
				else
				{
					close(reservation_sock);
					close(relayed_sock);
					reservation_sock = -1;
					relayed_sock = -1;
				}
			}
		}

		quit_loop++;
	}

	if (relayed_sock == -1)
	{
		turnserver_send_error(transport_protocol, sock, method,
			message->msg->turn_msg_id, 500, saddr, saddr_size, account->key);
		return -1;
	}

	if (getsockname(relayed_sock, (struct sockaddr*)&relayed_addr, &relayed_size)
		!= 0)
	{

		close(relayed_sock);
		return -1;
	}

	if (relayed_addr.ss_family == AF_INET)
	{
		port = ntohs(((struct sockaddr_in*)&relayed_addr)->sin_port);
	}
	else /* IPv6 */
	{
		port = ntohs(((struct sockaddr_in6*)&relayed_addr)->sin6_port);
	}

	desc = allocation_desc_new(message->msg->turn_msg_id, transport_protocol,
		account->username, account->key, account->realm,
		message->nonce->turn_attr_nonce, (address_type*)&relayed_addr, daddr,
		saddr, sizeof(struct sockaddr_storage), lifetime);

	if (!desc)
	{
		/* send error response with code 500 */
		turnserver_send_error(transport_protocol, sock, method,
			message->msg->turn_msg_id, 500, saddr, saddr_size, account->key);
		close(relayed_sock);
		return -1;
	}

	/* init token bucket */
	if (account->state == AUTHORIZED)
	{
		/* store it in bytes */
		desc->bucket_capacity = bandwidth_per_allocation * 1000;
	}
	else
	{
		/* store it in bytes */
		desc->bucket_capacity = restricted_bandwidth * 1000;
	}

	desc->bucket_tokenup = desc->bucket_capacity;
	desc->bucket_tokendown = desc->bucket_capacity;

	desc->relayed_transport_protocol =
		message->requested_transport->turn_attr_protocol;

	/* increment number of allocations */
	account->allocations++;
	debug(DBG_ATTR, "Account %s, allocations used: %u\n", account->username,
		account->allocations);


	/* assign the sockets to the allocation */
	desc->relayed_sock = relayed_sock;

	if (message->requested_transport->turn_attr_protocol == IPPROTO_TCP)
	{
		desc->relayed_sock_tcp = relayed_sock_tcp;
	}

	desc->tuple_sock = sock;
	/* add to the list */
	allocation_list_add(_allocation_list, desc);

	/* send back the success response */
send_success_response:
	{
		/* header, relayed-address, lifetime, reservation-token (if any),
		 * xor-mapped-address, username, software, message-integrity, fingerprint
		 */
		struct iovec iov[12];
		struct turn_msg_hdr* hdr = NULL;
		struct turn_attr_hdr* attr = NULL;
		size_t idx = 0;

		if (!(hdr = turn_msg_allocate_response_create(0, message->msg->turn_msg_id,
			&iov[idx])))
		{
			turnserver_send_error(transport_protocol, sock, method,
				message->msg->turn_msg_id, 500, saddr, saddr_size, desc->key);
			return -1;
		}
		idx++;

		/* required attributes */
		if (!(attr = turn_attr_xor_relayed_address_create(sock, transport_protocol, STUN_MAGIC_COOKIE, message->msg->turn_msg_id, &iov[idx])))
		{
			iovec_free_data(iov, idx);
			turnserver_send_error(transport_protocol, sock, method,
				message->msg->turn_msg_id, 500, saddr, saddr_size, desc->key);
			return -1;
		}
		hdr->turn_msg_len += iov[idx].iov_len;
		idx++;

		if (!(attr = turn_attr_lifetime_create(lifetime, &iov[idx])))
		{
			iovec_free_data(iov, idx);
			turnserver_send_error(transport_protocol, sock, method,
				message->msg->turn_msg_id, 500, saddr, saddr_size, desc->key);
			return -1;
		}
		hdr->turn_msg_len += iov[idx].iov_len;
		idx++;


		if (transport_protocol == IPPROTO_TCP)
		{
			auto tcpsocket = (tcp_socket*)sock;
			port = tcpsocket->remote_endpoint().port();
		}
		else if (transport_protocol == IPPROTO_UDP)
		{
			auto tcpsocket = (udp_socket*)sock;
			port = tcpsocket->remote_endpoint().port();
		}
		else {
			iovec_free_data(iov, idx);
			return -1;
		}

		;
		if (!(attr = turn_attr_xor_mapped_address_create(sock, transport_protocol, STUN_MAGIC_COOKIE, message->msg->turn_msg_id, &iov[idx])))
		{
			iovec_free_data(iov, idx);
			turnserver_send_error(transport_protocol, sock, method,
				message->msg->turn_msg_id, 500, saddr, saddr_size, desc->key);
			return -1;
		}
		hdr->turn_msg_len += iov[idx].iov_len;
		idx++;

		if (reservation_port)
		{
			/* server has stored a socket/port */
			debug(DBG_ATTR, "Send a reservation-token attribute\n");
			if (!(attr = turn_attr_reservation_token_create(reservation_token,
				&iov[idx])))
			{
				iovec_free_data(iov, idx);
				turnserver_send_error(transport_protocol, sock, method,
					message->msg->turn_msg_id, 500, saddr, saddr_size,
					desc->key);
				return -1;
			}
			hdr->turn_msg_len += iov[idx].iov_len;
			idx++;
		}

		/* software (not fatal if it cannot be allocated) */
		if ((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION,
			sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
		{
			hdr->turn_msg_len += iov[idx].iov_len;
			idx++;
		}

		if (turn_add_message_integrity(iov, &idx, desc->key, sizeof(desc->key), 1)
			== -1)
		{
			iovec_free_data(iov, idx);
			turnserver_send_error(transport_protocol, sock, method,
				message->msg->turn_msg_id, 500, saddr, saddr_size, desc->key);
			return -1;
		}

		debug(DBG_ATTR, "Allocation successful, send success allocate response\n");

		if (turn_send_message(transport_protocol, sock, saddr, saddr_size,
			ntohs(hdr->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, idx)
			== -1)
		{
			debug(DBG_ATTR, "turn_send_message failed\n");
		}

		iovec_free_data(iov, idx);
	}

	return 0;
}

/**
 * \brief Process a TURN CreatePermission request.
 * \param transport_protocol transport protocol used
 * \param sock socket
 * \param message TURN message
 * \param saddr source address of the message
 * \param saddr_size sizeof addr
 * \param desc allocation descriptor
 * \param speer TLS peer, if not NULL the connection is in TLS so response is
 * also in TLS
 * \return 0 if success, -1 otherwise
 */
int  turn_server::turnserver_process_createpermission_request(int transport_protocol,
	socket_base* sock, const struct turn_message* message, const address_type* saddr,
	socklen_t saddr_size, struct allocation_desc* desc)
{
	uint16_t hdr_msg_type = htons(message->msg->turn_msg_type);
	uint16_t method = STUN_GET_METHOD(hdr_msg_type);
	uint16_t peer_port = 0;
	uint8_t peer_addr[16];
	size_t len = 0;
	uint32_t cookie = htonl(STUN_MAGIC_COOKIE);
	uint8_t* p = (uint8_t*)&cookie;
	size_t i = 0;
	size_t j = 0;
	struct allocation_permission* alloc_permission = NULL;
	struct turn_msg_hdr* hdr = NULL;
	struct turn_attr_hdr* attr = NULL;
	struct iovec iov[4]; /* header, software, integrity, fingerprint */
	size_t idx = 0;
	char str[INET6_ADDRSTRLEN];
	string str2;
	char str3[INET6_ADDRSTRLEN];
	uint16_t port = 0;
	uint16_t port2 = 0;
	int family = 0;

	debug(DBG_ATTR, "CreatePermission request received\n");

	if (message->xor_peer_addr_overflow)
	{
		/* too many XOR-PEER-ADDRESS attributes => error 508 */
		debug(DBG_ATTR, "Too many XOR-PEER-ADDRESS attributes\n");
		turnserver_send_error(transport_protocol, sock, method,
			message->msg->turn_msg_id, 508, saddr, saddr_size, desc->key);
		return -1;
	}

	if (!message->peer_addr[0])
	{
		/* no XOR-PEER-ADDRESS => error 400 */
		debug(DBG_ATTR, "Missing address attribute\n");
		turnserver_send_error(transport_protocol, sock, method,
			message->msg->turn_msg_id, 400, saddr, saddr_size, desc->key);
		return -1;
	}

	/* get string representation of addresses for syslog */
	if (desc->relayed_addr.ss_family == AF_INET)
	{
		inet_ntop(AF_INET, &((struct sockaddr_in*)&desc->relayed_addr)->sin_addr,
			str3, INET6_ADDRSTRLEN);
		port = ntohs(((struct sockaddr_in*)&desc->relayed_addr)->sin_port);
	}
	else /* IPv6 */
	{
		inet_ntop(AF_INET6, &((struct sockaddr_in6*)&desc->relayed_addr)->sin6_addr,
			str3, INET6_ADDRSTRLEN);
		port = ntohs(((struct sockaddr_in6*)&desc->relayed_addr)->sin6_port);
	}

	if (transport_protocol == IPPROTO_TCP)
	{
		auto tcpsocket = (tcp_socket*)sock;
		str2 = tcpsocket->remote_endpoint().address().to_string();
		port2 = tcpsocket->remote_endpoint().port();
	}
	else if (transport_protocol == IPPROTO_UDP)
	{
		auto tcpsocket = (udp_socket*)sock;
		str2 = tcpsocket->remote_endpoint().address().to_string();
		port2 = tcpsocket->remote_endpoint().port();
	}

	/* check address family for all XOR-PEER-ADDRESS attributes against the
	 * relayed ones
	 */
	for (i = 0; i < XOR_PEER_ADDRESS_MAX && message->peer_addr[i]; i++)
	{
		switch (message->peer_addr[i]->turn_attr_family)
		{
		case STUN_ATTR_FAMILY_IPV4:
			len = 4;
			family = AF_INET;
			break;
		case STUN_ATTR_FAMILY_IPV6:
			len = 16;
			family = AF_INET6;
			break;
		default:
			return -1;
		}

		if ((desc->relayed_addr.ss_family != family))
		{
			/* peer family mismatch => error 443 */
			debug(DBG_ATTR, "Peer family mismatch\n");
			turnserver_send_error(transport_protocol, sock, method,
				message->msg->turn_msg_id, 443, saddr, saddr_size, desc->key);
			return -1;
		}

		/* now check that address is not denied */
		memcpy(peer_addr, message->peer_addr[i]->turn_attr_address, len);
		peer_port = ntohs(message->peer_addr[i]->turn_attr_port);

		if (turn_xor_address_cookie(message->peer_addr[i]->turn_attr_family,
			peer_addr, &peer_port, p, message->msg->turn_msg_id) == -1)
		{
			return -1;
		}

		inet_ntop(family, peer_addr, str, INET6_ADDRSTRLEN);

		/* if one of the addresses is denied, directly send
		 * a CreatePermission error response.
		 */
		if (turnserver_is_address_denied(peer_addr, len, peer_port))
		{
			debug(DBG_ATTR,
				"TurnServer does not permit to install permission to %s\n", str);
			turnserver_send_error(transport_protocol, sock, method,
				message->msg->turn_msg_id, 403, saddr, saddr_size, desc->key);
			return -1;
		}
	}

	for (j = 0; j < XOR_PEER_ADDRESS_MAX && message->peer_addr[j]; j++)
	{
		/* copy peer address */
		switch (message->peer_addr[j]->turn_attr_family)
		{
		case STUN_ATTR_FAMILY_IPV4:
			len = 4;
			family = AF_INET;
			break;
		case STUN_ATTR_FAMILY_IPV6:
			len = 16;
			family = AF_INET6;
			break;
		default:
			return -1;
		}

		memcpy(peer_addr, message->peer_addr[j]->turn_attr_address, len);
		peer_port = ntohs(message->peer_addr[j]->turn_attr_port);

		if (turn_xor_address_cookie(message->peer_addr[j]->turn_attr_family,
			peer_addr, &peer_port, p, message->msg->turn_msg_id) == -1)
		{
			return -1;
		}

		inet_ntop(family, peer_addr, str, INET6_ADDRSTRLEN);

		/* find a permission */
		alloc_permission = allocation_desc_find_permission(desc,
			desc->relayed_addr.ss_family, peer_addr);

		/* update or create allocation permission on that peer */
		if (!alloc_permission)
		{
			debug(DBG_ATTR, "Install permission for %s %u\n", str, peer_port);
			allocation_desc_add_permission(desc, TURN_DEFAULT_PERMISSION_LIFETIME,
				desc->relayed_addr.ss_family, peer_addr);
		}
		else
		{
			debug(DBG_ATTR, "Refresh permission\n");
			allocation_permission_set_timer(alloc_permission,
				TURN_DEFAULT_PERMISSION_LIFETIME);
		}
	}

	/* send a CreatePermission success response */
	if (!(hdr = turn_msg_createpermission_response_create(0, message->msg->turn_msg_id, &iov[idx])))
	{
		turnserver_send_error(transport_protocol, sock, method,
			message->msg->turn_msg_id, 500, saddr, saddr_size, desc->key);
		return -1;
	}
	idx++;

	/* software (not fatal if it cannot be allocated) */
	if ((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION,
		sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
	{
		hdr->turn_msg_len += iov[idx].iov_len;
		idx++;
	}

	if (turn_add_message_integrity(iov, &idx, desc->key, sizeof(desc->key), 1)
		== -1)
	{
		iovec_free_data(iov, idx);
		turnserver_send_error(transport_protocol, sock, method,
			message->msg->turn_msg_id, 500, saddr, saddr_size, desc->key);
		return -1;
	}

	debug(DBG_ATTR,
		"CreatePermission successful, send success CreatePermission response\n");

	/* finally send the response */

	if (turn_send_message(transport_protocol, sock, saddr, saddr_size, ntohs(hdr->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, idx)
		== -1)
	{
		debug(DBG_ATTR, "turn_send_message failed\n");
	}

	iovec_free_data(iov, idx);
	return 0;
}


/**
 * \brief Process a TURN Refresh request.
 * \param transport_protocol transport protocol used
 * \param sock socket
 * \param message TURN message
 * \param saddr source address of the message
 * \param saddr_size sizeof addr
 * \param allocation_list list of allocations
 * \param desc allocation descriptor
 * \param account account descriptor
 * \param speer TLS peer, if not NULL the connection is in TLS so response is
 * also in TLS
 * \return 0 if success, -1 otherwise
 */
int  turn_server::turnserver_process_refresh_request(int transport_protocol, socket_base* sock,
	const struct turn_message* message, const address_type* saddr,
	socklen_t saddr_size, struct allocation_desc* desc, struct account_desc* account)
{
	uint16_t hdr_msg_type = htons(message->msg->turn_msg_type);
	uint16_t method = STUN_GET_METHOD(hdr_msg_type);
	uint32_t lifetime = 0;
	struct iovec iov[5]; /* header, lifetime, software, integrity, fingerprint */
	size_t idx = 0;
	struct turn_msg_hdr* hdr = NULL;
	struct turn_attr_hdr* attr = NULL;
	uint8_t key[16];
	string str;
	uint16_t port = 0;

	debug(DBG_ATTR, "Refresh request received!\n");

	/* save key from allocation as it could be freed if lifetime equals 0 */
	memcpy(key, desc->key, sizeof(desc->key));

	/* RFC6156: at this stage server knows the 5-tuple and the allocation
	 * associated.
	 * No matter to know if the relayed address has a different address family
	 * than 5-tuple, so no need to have REQUESTED-ADDRESS-FAMILY attribute in
	 * Refresh request.
	 */

	 /* if REQUESTED-ADDRESS-FAMILY attribute is present and do not match relayed
	  * address ones => error 443
	  */
	if (message->requested_addr_family)
	{
		int family = 0;

		switch (message->requested_addr_family->turn_attr_family)
		{
		case STUN_ATTR_FAMILY_IPV4:
			family = AF_INET;
			break;
		case STUN_ATTR_FAMILY_IPV6:
			family = AF_INET6;
			break;
		default:
			return -1;
		}

		if (desc->relayed_addr.ss_family != family)
		{
			/* peer family mismatch => error 443 */
			debug(DBG_ATTR, "Peer family mismatch\n");
			turnserver_send_error(transport_protocol, sock, method,
				message->msg->turn_msg_id, 443, saddr, saddr_size, key);
			return -1;
		}
	}

	if (message->lifetime)
	{
		lifetime = htonl(message->lifetime->turn_attr_lifetime);

		debug(DBG_ATTR, "lifetime: %u seconds\n", lifetime);

		/* adjust lifetime (cannot be greater that maximum allowed) */
		lifetime = MIN(lifetime, TURN_MAX_ALLOCATION_LIFETIME);

		if (lifetime > 0)
		{
			/* lifetime cannot be smaller than default */
			lifetime = MAX(lifetime, TURN_DEFAULT_ALLOCATION_LIFETIME);
		}
	}
	else
	{
		/* cannot override default max value for allocation time */
		lifetime = MIN(allocation_lifetime, TURN_DEFAULT_ALLOCATION_LIFETIME);
	}

	if (transport_protocol == IPPROTO_TCP)
	{
		auto tcpsocket = (tcp_socket*)sock;
		str = tcpsocket->remote_endpoint().address().to_string();
		port = tcpsocket->remote_endpoint().port();
	}
	else if (transport_protocol == IPPROTO_UDP)
	{
		auto tcpsocket = (udp_socket*)sock;
		str = tcpsocket->remote_endpoint().address().to_string();
		port = tcpsocket->remote_endpoint().port();
	}


	if (lifetime > 0)
	{
		/* adjust lifetime */
		debug(DBG_ATTR, "Refresh allocation\n");
		allocation_desc_set_timer(desc, lifetime);
	}
	else
	{
		/* lifetime = 0 delete the allocation */
		/* protect the removing of the expired list if any */
		turnserver_block_realtime_signal();
		allocation_desc_set_timer(desc, 0); /* stop timeout */
		/* in case the allocation has expired during this statement */
		LIST_DEL(&desc->list2);
		turnserver_unblock_realtime_signal();

		allocation_list_remove(_allocation_list, desc);

		/* decrement allocations for the account */
		account->allocations--;
		debug(DBG_ATTR, "Account %s, allocations used: %u\n", account->username,
			account->allocations);
		debug(DBG_ATTR, "Explicit delete of allocation\n");
		if (account->allocations == 0 && account->is_tmp)
		{
			account_list_remove(NULL, account);
		}
	}

	if (!(hdr = turn_msg_refresh_response_create(0, message->msg->turn_msg_id, &iov[idx])))
	{
		turnserver_send_error(transport_protocol, sock, method,
			message->msg->turn_msg_id, 500, saddr, saddr_size, key);
		return -1;
	}
	idx++;

	if (!(attr = turn_attr_lifetime_create(lifetime, &iov[idx])))
	{
		iovec_free_data(iov, idx);
		turnserver_send_error(transport_protocol, sock, method,
			message->msg->turn_msg_id, 500, saddr, saddr_size, key);
		return -1;
	}
	hdr->turn_msg_len += iov[idx].iov_len;
	idx++;

	/* software (not fatal if it cannot be allocated) */
	if ((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION,
		sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
	{
		hdr->turn_msg_len += iov[idx].iov_len;
		idx++;
	}

	if (turn_add_message_integrity(iov, &idx, key, sizeof(key), 1) == -1)
	{
		iovec_free_data(iov, idx);
		turnserver_send_error(transport_protocol, sock, method,
			message->msg->turn_msg_id, 500, saddr, saddr_size, key);
		return -1;
	}

	debug(DBG_ATTR, "Refresh successful, send success refresh response\n");

	/* finally send the response */
	if (turn_send_message(transport_protocol, sock, saddr, saddr_size,
		ntohs(hdr->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, idx)
		== -1)
	{
		debug(DBG_ATTR, "turn_send_message failed\n");
	}

	iovec_free_data(iov, idx);
	return 0;
}




int turn_server::socket_create(enum protocol_type type, const char* addr, uint16_t port, int reuse, int nodelay)
{
	int sock = -1;
	struct addrinfo hints;
	struct addrinfo* res = NULL;
	struct addrinfo* p = NULL;
	char service[8];

	snprintf(service, sizeof(service), "%u", port);
	service[sizeof(service) - 1] = 0x00;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = (type == TCP ? SOCK_STREAM : SOCK_DGRAM);
	hints.ai_protocol = (type == TCP ? IPPROTO_TCP : IPPROTO_UDP);
	hints.ai_flags = AI_PASSIVE;

	if (getaddrinfo(addr, service, &hints, &res) != 0)
	{
		return -1;
	}

	for (p = res; p; p = p->ai_next)
	{
		int on = 1;

		sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (sock == -1)
		{
			continue;
		}

		if (reuse)
		{
			setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int));
		}

		if (type == TCP && nodelay)
		{
			setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(int));
		}

		/* accept IPv6 and IPv4 on the same socket */
		on = 0;
		setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(int));

		if (bind(sock, p->ai_addr, p->ai_addrlen) == -1)
		{
			close(sock);
			sock = -1;
			continue;
		}

		/* socket bound, break the loop */
		break;
	}

	freeaddrinfo(res);
	p = NULL;

	return sock;
}

/**
 * \brief Block realtime signal used in TurnServer.
 *
 * This is used to prevent race conditions when adding or removing objects in
 * expired list (which is mainly done in signal handler and in purge loop).
 */
void turn_server::turnserver_block_realtime_signal(void)
{
	sigset_t mask;

	sigemptyset(&mask);
	sigaddset(&mask, SIGRT_EXPIRE_ALLOCATION);
	sigaddset(&mask, SIGRT_EXPIRE_PERMISSION);
	sigaddset(&mask, SIGRT_EXPIRE_CHANNEL);
	sigaddset(&mask, SIGRT_EXPIRE_TOKEN);
	sigprocmask(SIG_BLOCK, &mask, NULL);
}

/**
 * \brief Unblock realtime signal used in TurnServer.
 *
 * This is used to prevent race conditions when adding or removing objects in
 * expired list (which is mainly done in signal handler and in purge loop).
 */
void turn_server::turnserver_unblock_realtime_signal(void)
{
	sigset_t mask;

	sigemptyset(&mask);
	sigaddset(&mask, SIGRT_EXPIRE_ALLOCATION);
	sigaddset(&mask, SIGRT_EXPIRE_PERMISSION);
	sigaddset(&mask, SIGRT_EXPIRE_CHANNEL);
	sigaddset(&mask, SIGRT_EXPIRE_TOKEN);
	sigprocmask(SIG_UNBLOCK, &mask, NULL);
}


#pragma region 发送socket

int turn_server::turn_send_message(int transport_protocol, socket_base* sock,
	const address_type* remoteaddr, int remoteAddrSize, size_t total_len,
	const  iovec* iov, size_t iovlen)
{
	if (transport_protocol == IPPROTO_UDP)
	{
		return turn_udp_send(sock, remoteaddr, remoteAddrSize, iov, iovlen);
	}
	else /* TCP */
	{
		return turn_tcp_send(sock, iov, iovlen);
	}
}

int turn_server::turn_udp_send(socket_base* sock, const address_type* remoteaddr, int remoteAddrSize, const struct iovec* iov, size_t iovlen)
{
	ssize_t len = -1;
	struct msghdr msg;
	memset(&msg, 0x00, sizeof(struct msghdr));

	msg.msg_name = (struct sockaddr*)(&remoteaddr);//此处的转换可能无效，日后调试需注意
	msg.msg_namelen = remoteAddrSize;
	msg.msg_iov = (struct iovec*)iov;
	msg.msg_iovlen = iovlen;

	len = manager.udp_send(&msg, (udp_socket*)sock);
	return len;
}

int turn_server::turn_tcp_send(socket_base* sock, const struct iovec* iov, size_t iovlen)
{
	ssize_t len = -1;
	struct msghdr msg;
	memset(&msg, 0x00, sizeof(struct msghdr));
	msg.msg_iov = (struct iovec*)iov;
	msg.msg_iovlen = iovlen;
	///////////
	len = manager.tcp_send(&msg, (tcp_socket*)sock);
	return len;
}

int turn_server::turn_tls_send(struct tls_peer* peer, const struct sockaddr* addr,
	socklen_t addr_size, size_t total_len, const struct iovec* iov,
	size_t iovlen)
{
	debug(DBG_ATTR, "connot use tls\n");
	return -1;
	//char* buf = NULL;
	//char* p = NULL;
	//size_t i = 0;
	//ssize_t nb = -1;

	//buf = (char*)malloc(total_len);
	//if (!buf)
	//{
	//	return -1;
	//}

	//p = buf;

	///* convert the iovec into raw buffer
	// * cannot send iovec with libssl.
	// */
	//for (i = 0; i < iovlen; i++)
	//{
	//	memcpy(p, iov[i].iov_base, iov[i].iov_len);
	//	p += iov[i].iov_len;
	//}

	//nb = tls_peer_write(peer, buf, total_len, addr, addr_size);
	//free(buf);
	//return nb;
}

/**
 * \brief Send a TURN Error response.
 * \param transport_protocol transport protocol to send the message
 * \param sock socket
 * \param method STUN/TURN method
 * \param id transaction ID
 * \param saddr address to send
 * \param saddr_size sizeof address
 * \param error error code
 * \param speer TLS peer, if not NULL, send the error in TLS
 * \param key MD5 hash of account, if present, MESSAGE-INTEGRITY will be added
 * \note Some error codes cannot be sent using this function (420, 438, ...).
 * \return 0 if success, -1 otherwise
 */
int  turn_server::turnserver_send_error(int transport_protocol, socket_base* sock, int method,
	const uint8_t* id, int error, const address_type* saddr,
	socklen_t saddr_size, unsigned char* key)
{
	struct iovec iov[16]; /* should be sufficient */
	struct turn_msg_hdr* hdr = NULL;
	struct turn_attr_hdr* attr = NULL;
	size_t idx = 0;

	switch (error)
	{
	case 400: /* Bad request */
		hdr = turn_error_response_400(method, id, &iov[idx], &idx);
		break;
	case 403: /* Forbidden */
		hdr = turn_error_response_403(method, id, &iov[idx], &idx);
		break;
	case 437: /* Alocation mismatch */
		hdr = turn_error_response_437(method, id, &iov[idx], &idx);
		break;
	case 440: /* Address family not supported */
		hdr = turn_error_response_440(method, id, &iov[idx], &idx);
		break;
	case 441: /* Wrong credentials */
		hdr = turn_error_response_441(method, id, &iov[idx], &idx);
		break;
	case 442: /* Unsupported transport protocol */
		hdr = turn_error_response_442(method, id, &iov[idx], &idx);
		break;
	case 443: /* Peer address family mismatch */
		hdr = turn_error_response_443(method, id, &iov[idx], &idx);
		break;
	case 446: /* Connection already exists (RFC6062) */
		hdr = turn_error_response_446(method, id, &iov[idx], &idx);
		break;
	case 447: /* Connection timeout or failure (RFC6062) */
		hdr = turn_error_response_447(method, id, &iov[idx], &idx);
		break;
	case 486: /* Allocation quota reached */
		hdr = turn_error_response_486(method, id, &iov[idx], &idx);
		break;
	case 500: /* Server error */
		hdr = turn_error_response_500(method, id, &iov[idx], &idx);
		break;
	case 508: /* Insufficient port capacity */
		hdr = turn_error_response_508(method, id, &iov[idx], &idx);
		break;
	default:
		break;
	}

	if (!hdr)
	{
		return -1;
	}

	/* software (not fatal if it cannot be allocated) */
	if ((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION,
		sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
	{
		hdr->turn_msg_len += iov[idx].iov_len;
		idx++;
	}

	if (key)
	{
		if (turn_add_message_integrity(iov, &idx, key, 16, 1) == -1)
		{
			/* MESSAGE-INTEGRITY option has to be in message, so
			 * deallocate ressources and return
			 */
			iovec_free_data(iov, idx);
			return -1;
		}
		/* function above already set turn_msg_len field to big endian */
	}
	else
	{
		turn_add_fingerprint(iov, &idx); /* not fatal if not successful */

		/* convert to big endian */
		hdr->turn_msg_len = htons(hdr->turn_msg_len);
	}

	/* finally send the response */
	if (turn_send_message(transport_protocol, sock, saddr, saddr_size,
		ntohs(hdr->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, idx)
		== -1)
	{
		debug(DBG_ATTR, "turn_send_message failed\n");
	}

	iovec_free_data(iov, idx);
	return 0;
}

#pragma endregion
