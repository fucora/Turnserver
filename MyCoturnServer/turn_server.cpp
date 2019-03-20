
#include "turn_server.h"


unsigned long bandwidth = 1024;//带宽
list_head* _allocation_list;

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
	address_type remoteaddr = address_type(tcpsocket->remote_endpoint().address());
	address_type localaddr = address_type(tcpsocket->local_endpoint().address());
	int remoteAddrSize = tcpsocket->local_endpoint().size();

	MessageHandle(*buf, lenth, IPPROTO_TCP, remoteaddr, localaddr,remoteAddrSize);
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
	uint16_t type = 0;
	if (lenth < 4)
	{
		debug(DBG_ATTR, "Size too short\n");
		return;
	}
	memcpy(&type, data, sizeof(uint16_t));
	type = ntohs(type);

	/* is it a ChannelData message (bit 0 and 1 are not set to 0) ? */
	if (TURN_IS_CHANNELDATA(type))
	{
		return turnserver_process_channeldata(transport_protocol, type, data, lenth, remoteaddr, localaddr, remoteAddrSize, _allocation_list);
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
		(desc->tuple.client_addr.ss_family == AF_INET ||
		(desc->tuple.client_addr.ss_family == AF_INET6 &&
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
	return (ss->ss_family == AF_INET) ? sizeof(struct sockaddr_in) :
		sizeof(struct sockaddr_in6);
}

