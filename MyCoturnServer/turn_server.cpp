
#include "turn_server.h"


unsigned long bandwidth = 1024;//带宽
list_head* _allocation_list;
char* nonce_key = "hieKedq";
int turn_tcp = 1;
char* realm = "domain.org";

#define SOFTWARE_DESCRIPTION "TurnServer 1"  

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
	address_type remoteaddr = address_type(tcpsocket->remote_endpoint().address());
	address_type localaddr = address_type(tcpsocket->local_endpoint().address());
	int remoteAddrSize = tcpsocket->local_endpoint().size();

	MessageHandle(*buf, lenth, IPPROTO_TCP, remoteaddr, localaddr, remoteAddrSize);
	/*int method = turn_agreement::stun_get_method_str(buf, lenth);*/
	printf("收到tcp消息");
}

void turn_server::onUdpMessage(buffer_type* buf, int lenth, udp_socket* udpsocket) {
	address_type remoteaddr = address_type(udpsocket->remote_endpoint().address());
	address_type localaddr = address_type(udpsocket->local_endpoint().address());
	int remoteAddrSize = udpsocket->local_endpoint().size();
	MessageHandle(*buf, lenth, IPPROTO_UDP, remoteaddr, localaddr, remoteAddrSize);
	printf("收到udp消息");
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int turn_server::MessageHandle(buffer_type data, int lenth, int transport_protocol, address_type remoteaddr, address_type localaddr, int remoteAddrSize)
{
	struct turn_message message;
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
		(method != TURN_METHOD_CONNECT || !turn_tcp) &&
		(method != TURN_METHOD_CONNECTIONBIND || !turn_tcp))
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
		if (htonl(crc) != (message.fingerprint->turn_attr_crc ^ htonl(
			STUN_FINGERPRINT_XOR_VALUE)))
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
			if (!(error = turn_error_response_401(method, message.msg->turn_msg_id, realm, nonce, sizeof(nonce), iov, &idx)))
			{
				turnserver_send_error(transport_protocol, sock, method, message.msg->turn_msg_id, 500, saddr, saddr_size, NULL);
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

			if (turn_send_message(transport_protocol, sock, speer, saddr, saddr_size, ntohs(error->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, idx) == -1)
			{
				debug(DBG_ATTR, "turn_send_message failed\n");
			}
			/* free sent data */
			iovec_free_data(iov, idx);
			return 0;
		}
	}
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
	address_type remoteaddr, address_type localaddr, int remoteAddrSize, list_head* allocation_list)
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
int turn_server::turnserver_send_error(int transport_protocol, int sock, int method,
	const uint8_t* id, int error, const struct sockaddr* saddr,
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
	if ((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION, sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
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
	if (turn_send_message(transport_protocol, sock, saddr, saddr_size, ntohs(hdr->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, idx) == -1)
	{
		debug(DBG_ATTR, "turn_send_message failed\n");
	}

	iovec_free_data(iov, idx);
	return 0;
}

#pragma region 发送socket

int turn_server::turn_send_message(int transport_protocol, int sock,
	const struct sockaddr* addr, socklen_t addr_size, size_t total_len,
	const struct iovec* iov, size_t iovlen)
{
	if (transport_protocol == IPPROTO_UDP)
	{
		return turn_udp_send(sock, addr, addr_size, iov, iovlen);
	}
	else /* TCP */
	{
		return turn_tcp_send(sock, iov, iovlen);
	}
}

int turn_server::turn_udp_send(int sock, const struct sockaddr* addr, socklen_t addr_size, const struct iovec* iov, size_t iovlen)
{
	ssize_t len = -1;

#if !defined(_WIN32) && !defined(_WIN64)
	struct msghdr msg;

	memset(&msg, 0x00, sizeof(struct msghdr));
	msg.msg_name = (struct sockaddr*)addr;
	msg.msg_namelen = addr_size;
	msg.msg_iov = (struct iovec*)iov;
	msg.msg_iovlen = iovlen;
	len = sendmsg(sock, &msg, 0);
#else
	len = sock_writev(sock, iov, iovlen, addr, addr_size);
#endif
	return len;
}

int turn_server::turn_tcp_send(int sock, const struct iovec* iov, size_t iovlen)
{
	ssize_t len = -1;

#if !defined(_WIN32) && !defined(_WIN64)
	struct msghdr msg;

	memset(&msg, 0x00, sizeof(struct msghdr));
	msg.msg_iov = (struct iovec*)iov;
	msg.msg_iovlen = iovlen;
	len = sendmsg(sock, &msg, 0);
#else
	len = sock_writev(sock, iov, iovlen, NULL, 0);
#endif
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

#pragma endregion
