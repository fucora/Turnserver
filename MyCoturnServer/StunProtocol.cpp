#include "StunProtocol.h"

#define STUN_HEADER_LENGTH (20)
int turn_tcp = 1;


StunProtocol::StunProtocol()
{
}


#pragma region 解析协议的方法

/* count of XOR-PEER-ADDRESS attribute */
size_t xor_peer_address_nb = 0;
size_t unknown_idx = 0;
StunProtocol::StunProtocol(char* buf, int datalength)
{
	if (datalength < 20) {
		return;
	}
	this->reuqestHeader = NULL;

	char* allBufferPtr = buf;

	this->reuqestHeader = (struct turn_msg_hdr*)allBufferPtr;
	size_t requestlen = ntohs(this->reuqestHeader->turn_msg_len);

	if ((requestlen + 20) > datalength)
	{
		return;
	}
	allBufferPtr += 20;
	if (requestlen % 4) {
		return;
	}

	while (requestlen >= 4) {
		struct turn_attr_hdr* attr = (struct turn_attr_hdr*)allBufferPtr;
		/* FINGERPRINT MUST be the last attributes if present */
		if (this->fingerprint)
		{
			/* when present, the FINGERPRINT attribute MUST be the last attribute */
			/* ignore other message
			 */
			return;
		}

		if (this->message_integrity && ntohs(attr->turn_attr_type) != STUN_ATTR_FINGERPRINT)
		{
			return;
		}
		this->getAttr(allBufferPtr, attr->turn_attr_type);
		requestlen -= (4 + ntohs(attr->turn_attr_len));
		allBufferPtr += (4 + ntohs(attr->turn_attr_len));

		size_t m = (4 + ntohs(attr->turn_attr_len)) % 4;
		if (m)
		{
			requestlen -= (4 - m);
			allBufferPtr += (4 - m);
		}
	}

	this->unknown_size = unknown_idx;
}
//获取协议里的attribute
int StunProtocol::getAttr(const char* bufferPtr, uint16_t attrtypeHotols)
{
	switch (ntohs(attrtypeHotols))
	{
	case STUN_ATTR_MAPPED_ADDRESS:
		mapped_addr = (struct turn_attr_mapped_address*)bufferPtr;
		break;
	case STUN_ATTR_XOR_MAPPED_ADDRESS:
		xor_mapped_addr = (struct turn_attr_xor_mapped_address*)bufferPtr;
		break;
	case STUN_ATTR_ALTERNATE_SERVER:
		alternate_server = (struct turn_attr_alternate_server*)bufferPtr;
		break;
	case STUN_ATTR_NONCE:
		nonce = (struct turn_attr_nonce*)bufferPtr;
		break;
	case STUN_ATTR_REALM:
		realm = (struct turn_attr_realm*)bufferPtr;
		break;
	case STUN_ATTR_USERNAME:
		username = (struct turn_attr_username*)bufferPtr;
		break;
	case STUN_ATTR_ERROR_CODE:
		error_code = (struct turn_attr_error_code*)bufferPtr;
		break;
	case STUN_ATTR_UNKNOWN_ATTRIBUTES:
		unknown_attribute = (struct turn_attr_unknown_attribute*)bufferPtr;
		break;
	case STUN_ATTR_MESSAGE_INTEGRITY:
		message_integrity = (struct turn_attr_message_integrity*)bufferPtr;
		break;
	case STUN_ATTR_FINGERPRINT:
		fingerprint = (struct turn_attr_fingerprint*)bufferPtr;
		break;
	case STUN_ATTR_SOFTWARE:
		software = (struct turn_attr_software*)bufferPtr;
		break;
	case TURN_ATTR_CHANNEL_NUMBER:
		channel_number = (struct turn_attr_channel_number*)bufferPtr;
		break;
	case TURN_ATTR_LIFETIME:
		lifetime = (struct turn_attr_lifetime*)bufferPtr;
		break;
	case TURN_ATTR_XOR_PEER_ADDRESS:
		if (xor_peer_address_nb < XOR_PEER_ADDRESS_MAX)
		{
			peer_addr[xor_peer_address_nb] = (struct turn_attr_xor_peer_address*)bufferPtr;
			xor_peer_address_nb++;
		}
		else
		{
			/* too many XOR-PEER-ADDRESS attribute,
			 * this will inform process_createpermission() to reject the
			 * request with a 508 error
			 */
			xor_peer_addr_overflow = 1;
		}
		break;
	case TURN_ATTR_DATA:
		data = (struct turn_attr_data*)bufferPtr;
		break;
	case TURN_ATTR_XOR_RELAYED_ADDRESS:
		relayed_addr = (struct turn_attr_xor_relayed_address*)bufferPtr;
		break;
	case TURN_ATTR_EVEN_PORT:
		even_port = (struct turn_attr_even_port*)bufferPtr;
		break;
	case TURN_ATTR_REQUESTED_TRANSPORT:
		requested_transport = (struct turn_attr_requested_transport*)bufferPtr;
		break;
	case TURN_ATTR_DONT_FRAGMENT:
		dont_fragment = (struct turn_attr_dont_fragment*)bufferPtr;
		break;
	case TURN_ATTR_RESERVATION_TOKEN:
		reservation_token = (struct turn_attr_reservation_token*)bufferPtr;
		break;
	case TURN_ATTR_REQUESTED_ADDRESS_FAMILY:
		requested_addr_family = (struct turn_attr_requested_address_family*)bufferPtr;
		break;
	case TURN_ATTR_CONNECTION_ID:
		connection_id = (struct turn_attr_connection_id*)bufferPtr;
		break;
	default:
		if (ntohs(attrtypeHotols) <= 0x7fff)
		{
			/* comprehension-required attribute but server does not understand
			 * it
			 */
			if (!this->unknown_size)
			{
				break;
			}
			this->unknown[unknown_idx] = htons(attrtypeHotols);
			this->unknown_size--;
			unknown_idx++;
		}
		break;
	}

	return 0;
}
#pragma endregion

void StunProtocol::addHeaderMsgLength(uint16_t ntohsVal) {
	//debug(DBG_ATTR, "add Length %d \n", ntohsVal);
	//debug(DBG_ATTR, "Total Length %d \n", ntohs(this->reuqestHeader->turn_msg_len) + ntohsVal);
	this->reuqestHeader->turn_msg_len = htons(ntohs(this->reuqestHeader->turn_msg_len) + ntohsVal);
}
#pragma region 对外方法
//是否是数据管道的数据
bool StunProtocol::IsChannelData()
{
	return TURN_IS_CHANNELDATA(this->reuqestHeader->turn_msg_type);
}
//获取请求类型，REQUEST，INDICATION,SUCCESS_RESP,ERROR_RESP
uint16_t StunProtocol::getRequestType()
{
	return ntohs(this->reuqestHeader->turn_msg_type);
}
//获取请求的消息总长度
uint16_t StunProtocol::getRequestLength()
{
	return	ntohs(this->reuqestHeader->turn_msg_len) + STUN_HEADER_LENGTH;
}

uint16_t StunProtocol::getRequestMethod()
{
	auto requesttype = getRequestType();
	return STUN_GET_METHOD(requesttype);
}
//获取消息的类型（REQUEST，INDICATION，SUCCESS_RESP，ERROR_RESP）
uint16_t StunProtocol::getResponseType()
{
	auto requesttype = getRequestType();
	return (requesttype) & 0x0110;
}



//是否是错误的请求
bool StunProtocol::IsErrorRequest(buffer_type buf)
{
	//检查是否是数据
	auto ischanneldata = IsChannelData();
	if (ischanneldata == true) {
		return false;
	}
	//检查请求类型是否合法
	auto responseType = getResponseType();
	if (responseType != STUN_REQUEST && responseType != STUN_INDICATION && responseType != STUN_SUCCESS_RESP && responseType != STUN_ERROR_RESP)
	{
		debug(DBG_ATTR, "Unknown message class\n");
		return true;
	}
	//检查请求方法是否合法
	auto requestmethod = getRequestMethod();
	if (requestmethod != STUN_METHOD_BINDING &&
		requestmethod != TURN_METHOD_ALLOCATE &&
		requestmethod != TURN_METHOD_REFRESH &&
		requestmethod != TURN_METHOD_CREATEPERMISSION &&
		requestmethod != TURN_METHOD_CHANNELBIND &&
		requestmethod != TURN_METHOD_SEND &&
		requestmethod != TURN_METHOD_DATA &&
		(requestmethod != TURN_METHOD_CONNECT || !turn_tcp) &&
		(requestmethod != TURN_METHOD_CONNECTIONBIND || !turn_tcp))
	{
		debug(DBG_ATTR, "Unknown method\n");
		return true;
	}
	//检查magic_cookie是否合法
	if (this->reuqestHeader->turn_msg_cookie != htonl(STUN_MAGIC_COOKIE))
	{
		debug(DBG_ATTR, "Bad magic cookie\n");
		return true;
	}
	/* check the fingerprint if present */
	if (this->fingerprint)
	{
		/* verify if CRC is valid */
		uint32_t crc = 0;
		crc = crc32_generate((const unsigned char*)buf, this->getRequestLength() - sizeof(struct turn_attr_fingerprint), 0);
		if (htonl(crc) != (this->fingerprint->turn_attr_crc ^ htonl(STUN_FINGERPRINT_XOR_VALUE)))
		{
			debug(DBG_ATTR, "Fingerprint mismatch\n");
			return true;
		}
		//应该不需要使用
		 /*	crc = crc32_generate((const unsigned char*)buf, getRequestLength() - sizeof(struct turn_attr_fingerprint), 0);
			 if (ntohl(crc ^ (uint32_t)STUN_FINGERPRINT_XOR_VALUE) != fingerprint->turn_attr_crc)
			 {
				 debug(DBG_ATTR, "Fingerprint mismatch\n");
				 return true;
			 }*/

	}
	return false;
}

void  StunProtocol::turn_error_response_400(int requestMethod, const uint8_t * transactionID)
{
	this->turn_msg_create(requestMethod, STUN_ERROR_RESP, 0, transactionID);
	this->turn_attr_error_create(400, STUN_ERROR_400);
}
void  StunProtocol::create_error_response_401(uint16_t requestMethod, const uint8_t * transactionID, char* realmstr, const uint8_t* nonce)
{
	this->turn_msg_create(requestMethod, STUN_ERROR_RESP, 0, transactionID);
	this->turn_attr_error_create(401, STUN_ERROR_401);
	this->turn_attr_realm_create(realmstr);
	this->turn_attr_nonce_create(nonce);
}

void  StunProtocol::turn_error_response_420(int requestMethod, const uint8_t * transactionID, const uint16_t * unknown, size_t unknown_size)
{
	this->turn_msg_create(requestMethod, STUN_ERROR_RESP, 0, transactionID);
	this->turn_attr_error_create(420, STUN_ERROR_420);
	this->turn_attr_unknown_attributes_create(unknown, unknown_size);
}

void  StunProtocol::turn_error_response_403(int requestMethod, const uint8_t * transactionID)
{
	this->turn_msg_create(requestMethod, STUN_ERROR_RESP, 0, transactionID);
	this->turn_attr_error_create(403, TURN_ERROR_403);
}
void  StunProtocol::turn_error_response_437(int requestMethod, const uint8_t * transactionID)
{
	this->turn_msg_create(requestMethod, STUN_ERROR_RESP, 0, transactionID);
	this->turn_attr_error_create(437, TURN_ERROR_437);
}

void  StunProtocol::turn_error_response_438(int requestMethod, const uint8_t * transactionID, const char* realm, const uint8_t * nonce)
{
	this->turn_msg_create(requestMethod, STUN_ERROR_RESP, 0, transactionID);
	this->turn_attr_error_create(438, STUN_ERROR_438);
	this->turn_attr_realm_create(realm);
	this->turn_attr_nonce_create(nonce);
}
void  StunProtocol::turn_error_response_440(int requestMethod, const uint8_t * transactionID)
{
	this->turn_msg_create(requestMethod, STUN_ERROR_RESP, 0, transactionID);
	this->turn_attr_error_create(440, TURN_ERROR_440);

}

void  StunProtocol::turn_error_response_441(int requestMethod, const uint8_t * transactionID)
{
	this->turn_msg_create(requestMethod, STUN_ERROR_RESP, 0, transactionID);
	this->turn_attr_error_create(441, TURN_ERROR_441);
}

void  StunProtocol::turn_error_response_442(int requestMethod, const uint8_t * transactionID)
{
	this->turn_msg_create(requestMethod, STUN_ERROR_RESP, 0, transactionID);
	this->turn_attr_error_create(442, TURN_ERROR_442);

}

void  StunProtocol::turn_error_response_443(int requestMethod, const uint8_t * transactionID)
{
	this->turn_msg_create(requestMethod, STUN_ERROR_RESP, 0, transactionID);
	this->turn_attr_error_create(443, TURN_ERROR_443);

}

void  StunProtocol::turn_error_response_446(int requestMethod, const uint8_t * transactionID)
{
	this->turn_msg_create(requestMethod, STUN_ERROR_RESP, 0, transactionID);
	this->turn_attr_error_create(446, TURN_ERROR_446);

}

void  StunProtocol::turn_error_response_447(int requestMethod, const uint8_t * transactionID)
{
	this->turn_msg_create(requestMethod, STUN_ERROR_RESP, 0, transactionID);
	this->turn_attr_error_create(447, TURN_ERROR_447);
}

void  StunProtocol::turn_error_response_486(int requestMethod, const uint8_t * transactionID)
{
	this->turn_msg_create(requestMethod, STUN_ERROR_RESP, 0, transactionID);
	this->turn_attr_error_create(486, TURN_ERROR_486);
}

void  StunProtocol::turn_msg_createpermission_response_create(const uint8_t * id)
{
	this->turn_msg_create(TURN_METHOD_CREATEPERMISSION, STUN_SUCCESS_RESP, 0, id);
}
int  StunProtocol::turn_attr_reservation_token_create(const uint8_t * token)
{
	this->reservation_token = (struct turn_attr_reservation_token*)malloc(sizeof(struct turn_attr_reservation_token));
	if (this->reservation_token == NULL) {
		return -1;
	}
	this->reservation_token->turn_attr_type = htons(TURN_ATTR_RESERVATION_TOKEN);
	this->reservation_token->turn_attr_len = htons(8);
	memcpy(this->reservation_token->turn_attr_token, token, 8);
	this->reservation_token_totalLength_nothsVal = sizeof(struct turn_attr_reservation_token);
	this->addHeaderMsgLength(this->reservation_token_totalLength_nothsVal);
}

void  StunProtocol::turn_error_response_500(int requestMethod, const uint8_t * transactionID)
{
	this->turn_msg_create(requestMethod, STUN_ERROR_RESP, 0, transactionID);
	this->turn_attr_error_create(500, STUN_ERROR_500);
}
void  StunProtocol::turn_error_response_508(int requestMethod, const uint8_t * transactionID)
{
	this->turn_msg_create(requestMethod, STUN_ERROR_RESP, 0, transactionID);
	this->turn_attr_error_create(508, TURN_ERROR_508);
}

void  StunProtocol::turn_attr_xor_mapped_address_create(const socket_base * sock, int transport_protocol, uint32_t cookie, const uint8_t * id)
{
	uint16_t port = 0;
	uint8_t family = 0;
	uint8_t* ptr = NULL; /* pointer on the address (IPv4 or IPv6) */
	
	  
	if (transport_protocol == IPPROTO_TCP)
	{
		auto tcpsocket = (tcp_socket*)sock;
		port = tcpsocket->remote_endpoint().port();

		sockaddr_in* addr_in = (sockaddr_in*)malloc(sizeof(sockaddr_in));
		addr_in->sin_addr.s_addr = inet_addr(tcpsocket->remote_endpoint().address().to_string().data());	  
	    ptr = (uint8_t*)(&addr_in->sin_addr); 

		if (tcpsocket->remote_endpoint().address().is_v4()) {
			family = STUN_ATTR_FAMILY_IPV4;
		}
		else
		{
			family = STUN_ATTR_FAMILY_IPV6;
		}
	}
	else if (transport_protocol == IPPROTO_UDP)
	{
		auto udpsocket = (udp_socket*)sock;
		port = udpsocket->remote_endpoint().port();

		sockaddr_in6* addr_in = (sockaddr_in6*)malloc(sizeof(sockaddr_in6)); 
		inet_pton(AF_INET6, udpsocket->remote_endpoint().address().to_string().data(), &addr_in->sin6_addr);		 
		ptr = (uint8_t*)(&addr_in->sin6_addr);

		if (udpsocket->remote_endpoint().address().is_v4()) {
			family = STUN_ATTR_FAMILY_IPV4;
		}
		else
		{
			family = STUN_ATTR_FAMILY_IPV6;
		}
	}

	return this->turn_attr_xor_address_create(STUN_ATTR_XOR_MAPPED_ADDRESS, ptr, port, family, cookie, id);
}
void  StunProtocol::turn_attr_xor_relayed_address_create(const struct sockaddr* address, int transport_protocol, uint32_t cookie, const uint8_t * id)
{
	uint8_t* ptr = NULL; /* pointer on the address (IPv4 or IPv6) */
	struct sockaddr_storage storage;
	uint16_t port = 0;
	uint8_t family = 0;
	switch (address->sa_family)
	{
	case AF_INET:
		memcpy(&storage, address, sizeof(struct sockaddr_in));
		ptr = (uint8_t*)&((struct sockaddr_in*)&storage)->sin_addr;
		port = ntohs(((struct sockaddr_in*)&storage)->sin_port);
		family = STUN_ATTR_FAMILY_IPV4;
		break;
	case AF_INET6:
		if (IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6*)address)->sin6_addr))
		{
			((struct sockaddr_in*)&storage)->sin_family = AF_INET;
			memcpy(&((struct sockaddr_in*)&storage)->sin_addr, &((struct sockaddr_in6*)address)->sin6_addr.s6_addr[12], 4);
			ptr = (uint8_t*)&((struct sockaddr_in*)&storage)->sin_addr;
			((struct sockaddr_in*)&storage)->sin_port = ((struct sockaddr_in6*)address)->sin6_port;
			memset(((struct sockaddr_in*)&storage)->sin_zero, 0x00, sizeof(((struct sockaddr_in*)&storage)->sin_zero));
			port = ntohs(((struct sockaddr_in*)&storage)->sin_port);
			family = STUN_ATTR_FAMILY_IPV4;
		}
		else
		{
			memcpy(&storage, address, sizeof(struct sockaddr_in6));
			ptr = (uint8_t*)&((struct sockaddr_in6*)&storage)->sin6_addr;
			port = ntohs(((struct sockaddr_in6*)&storage)->sin6_port);
			family = STUN_ATTR_FAMILY_IPV6;
		}
		break;
	default:
		return;
		break;
	}
	this->turn_attr_xor_address_create(TURN_ATTR_XOR_RELAYED_ADDRESS, ptr, port, family, cookie, id);
}

/**
 * \brief Helper function to create XOR-MAPPED-ADDRESS like.
 * \param type type
 * \param address network address
 * \param cookie magic cookie
 * \param id 96 bit transaction ID
 * \param iov vector
 * \return pointer on turn_attr_hdr or NULL if problem
 */
void  StunProtocol::turn_attr_xor_address_create(uint16_t type, uint8_t* pOfAddr, uint16_t port, uint8_t family, uint32_t cookie, const uint8_t * id)
{
	/* XOR-MAPPED-ADDRESS are the same as XOR-PEER-ADDRESS and
	 * XOR-RELAYED-ADDRESS
	 */
	size_t len = 0;
	uint8_t* p = (uint8_t*)&cookie;
	size_t i = 0;
	uint16_t msb_cookie = 0;

	if (family == STUN_ATTR_FAMILY_IPV4)
	{
		len = 4;
	}
	else
	{
		len = 16;
	}

	struct turn_attr_xor_mapped_address* ret = (struct turn_attr_xor_mapped_address*)malloc(sizeof(struct turn_attr_xor_mapped_address) + len);
	if (ret == NULL) {
		return;
	}
	/* XOR the address and port */

	/* host order port XOR most-significant 16 bits of the cookie */
	cookie = htonl(cookie);
	msb_cookie = ((uint8_t*)& cookie)[0] << 8 | ((uint8_t*)& cookie)[1];
	port ^= msb_cookie;
	/* IPv4/IPv6 XOR cookie (just the first four bytes of IPv6 address) */
	for (i = 0; i < 4; i++)
	{
		pOfAddr[i] ^= p[i];
	}

	/* end of IPv6 address XOR transaction ID */
	for (i = 4; i < len; i++)
	{
		pOfAddr[i] ^= id[i - 4];
	}
	ret->turn_attr_type = htons(type);
	/* reserved (1)  + family (1) + port (2) + address (variable) */
	ret->turn_attr_len = htons(4 + len);
	ret->turn_attr_reserved = 0;
	ret->turn_attr_family = family;
	ret->turn_attr_port = htons(port);
	memcpy(ret->turn_attr_address, pOfAddr, len);
	if (type == TURN_ATTR_XOR_RELAYED_ADDRESS)
	{
		this->relayed_addr = (struct turn_attr_xor_relayed_address*)ret;
		this->relayed_addr_totalLength_nothsVal = sizeof(struct turn_attr_xor_relayed_address) + len;
		this->addHeaderMsgLength(this->relayed_addr_totalLength_nothsVal);
	}
	else if (type == STUN_ATTR_XOR_MAPPED_ADDRESS)
	{
		this->xor_mapped_addr = ret;
		this->xor_mapped_addr_totalLength_nothsVal = sizeof(struct turn_attr_xor_mapped_address) + len;
		this->addHeaderMsgLength(this->xor_mapped_addr_totalLength_nothsVal);
	}
}

int  StunProtocol::turn_msg_channelbind_response_create(const uint8_t * id)
{
	return turn_msg_create(TURN_METHOD_CHANNELBIND, STUN_SUCCESS_RESP, 0, id);
}




int  StunProtocol::turn_attr_unknown_attributes_create(const uint16_t * unknown_attributes, size_t attr_size)
{
	size_t len = 0;
	size_t tmp_len = 0;
	size_t i = 0;
	uint16_t* ptr = NULL;
	/* length of the attributes MUST be a multiple of 4 bytes
	 * so it must be a pair number of attributes
	 */
	len = attr_size + (attr_size % 2);
	this->unknown_attribute = (struct turn_attr_unknown_attribute*)malloc(sizeof(struct turn_attr_unknown_attribute) + (len * 2));
	if (this->unknown_attribute == NULL) {
		return -1;
	}
	this->unknown_attribute->turn_attr_type = htons(STUN_ATTR_UNKNOWN_ATTRIBUTES);
	this->unknown_attribute->turn_attr_len = htons(attr_size);
	ptr = (uint16_t*)this->unknown_attribute->turn_attr_attributes;
	tmp_len = len;

	for (i = 0; i < attr_size; i++)
	{
		*ptr = htons(unknown_attributes[i]);
		tmp_len--;
		ptr++;
	}

	if (tmp_len)
	{
		/* take last attribute value */
		i--;
		*ptr = htons(unknown_attributes[i]);
	}
	this->unknown_attribute_totalLength_nothsVal = sizeof(struct turn_attr_unknown_attribute) + (len * 2);
	this->addHeaderMsgLength(this->unknown_attribute_totalLength_nothsVal);
}
int  StunProtocol::turn_attr_software_create(const char* software)
{
	uint16_t softwareSize = sizeof(software);
	size_t real_len = softwareSize;

	/* reason can be as long as 763 bytes */
	if (softwareSize > 763)
	{
		return -1;
	}

	/* real_len, attribute header size and padding must be a multiple of four */
	if ((real_len + 4) % 4)
	{
		real_len += (4 - (real_len % 4));
	}

	this->software = (struct turn_attr_software*)malloc(sizeof(struct turn_attr_software) + real_len);
	if (this->software == NULL) {
		return -1;
	}

	this->software->turn_attr_type = htons(STUN_ATTR_SOFTWARE);
	this->software->turn_attr_len = htons(softwareSize);
	memset(this->software->turn_attr_software, 0x00, real_len);
	memcpy(this->software->turn_attr_software, software, softwareSize);

	this->software_totalLength_nothsVal = sizeof(struct turn_attr_software) + real_len;
	this->addHeaderMsgLength(this->software_totalLength_nothsVal);
	return 1;
}

int StunProtocol::turn_nonce_is_stale(const char* noncekey)
{
	size_t noncekey_len = strlen(noncekey);
	uint8_t* nonce = this->nonce->turn_attr_nonce;
	size_t len = ntohs(this->nonce->turn_attr_len);
	uint32_t ct = 0;
	uint64_t ct64 = 0;
	time_t t = 0;
	unsigned char c = ':';
	MD5_CTX ctx;
	unsigned char md_buf[MD5_DIGEST_LENGTH];
	unsigned char md_txt[MD5_DIGEST_LENGTH * 2];

	if (len != (16 + MD5_DIGEST_LENGTH * 2))
	{
		return 1; /* bad nonce length */
	}

	if (sizeof(time_t) == 4) /* 32 bits */
	{
		uint32_convert(nonce, sizeof(time_t) * 2, &ct);
		memcpy(&t, &ct, 4);
	}
	else
	{
		uint64_convert(nonce, sizeof(time_t) * 2, &ct64);
		memcpy(&t, &ct64, 8);
	}

	MD5_Init(&ctx);
	MD5_Update(&ctx, nonce, 16); /* time */
	MD5_Update(&ctx, &c, 1);
	MD5_Update(&ctx, noncekey, noncekey_len);
	MD5_Final(md_buf, &ctx);

	hex_convert(md_buf, MD5_DIGEST_LENGTH, md_txt, sizeof(md_txt));

	if (memcmp(md_txt, nonce + 16, (MD5_DIGEST_LENGTH * 2)) != 0)
	{
		/* MD5 hash mismatch */
		return 1;
	}

	if (time(NULL) > t)
	{
		/* nonce stale */
		return 1;
	}
	return 0;
}

int StunProtocol::turn_add_message_integrity(const unsigned char* key, size_t key_len, int add_fingerprint)
{
	this->turn_attr_message_integrity_create(NULL);
	/* do not take into account the attribute itself */
	this->turn_calculate_integrity_hmac_iov(key, key_len);
	if (add_fingerprint)
	{
		this->turn_attr_fingerprint_create(0);
	}
	return 0;
}

int StunProtocol::turn_attr_message_integrity_create(const uint8_t * hmac)
{
	this->message_integrity = (struct turn_attr_message_integrity*)malloc(sizeof(struct turn_attr_message_integrity));
	if (this->message_integrity == NULL) {
		return -1;
	}

	this->message_integrity->turn_attr_type = htons(STUN_ATTR_MESSAGE_INTEGRITY);
	this->message_integrity->turn_attr_len = htons(20);

	if (hmac)
	{
		memcpy(this->message_integrity->turn_attr_hmac, hmac, 20);
	}
	else
	{
		memset(this->message_integrity->turn_attr_hmac, 0x00, 20);
	}
	this->message_integrity_totalLength_nothsVal = sizeof(struct turn_attr_message_integrity);
	this->addHeaderMsgLength(this->message_integrity_totalLength_nothsVal);
	return 1;
}

int StunProtocol::turn_calculate_integrity_hmac_iov(const unsigned char* key, size_t key_len)
{
	HMAC_CTX ctx;
	unsigned int md_len = SHA_DIGEST_LENGTH;
	size_t i = 0;

	/* MESSAGE-INTEGRITY uses HMAC-SHA1 */
	HMAC_CTX_init(&ctx);
	HMAC_Init(&ctx, key, key_len, EVP_sha1());

	if (this->reuqestHeader) {
		HMAC_Update(&ctx, (const unsigned char*)this->reuqestHeader, this->reuqestHeader_totalLength_nothsVal);
	}
	if (this->mapped_addr) {
		HMAC_Update(&ctx, (const unsigned char*)this->mapped_addr, this->mapped_addr_totalLength_nothsVal);
	}
	if (this->xor_mapped_addr) {
		HMAC_Update(&ctx, (const unsigned char*)this->xor_mapped_addr, this->xor_mapped_addr_totalLength_nothsVal);
	}
	if (this->alternate_server) {
		HMAC_Update(&ctx, (const unsigned char*)this->alternate_server, this->alternate_server_totalLength_nothsVal);
	}
	if (this->nonce) {
		HMAC_Update(&ctx, (const unsigned char*)this->nonce, this->nonce_totalLength_nothsVal);
	}
	if (this->realm) {
		HMAC_Update(&ctx, (const unsigned char*)this->realm, this->realm_totalLength_nothsVal);
	}
	if (this->username) {
		HMAC_Update(&ctx, (const unsigned char*)this->username, this->username_totalLength_nothsVal);
	}
	if (this->error_code) {
		HMAC_Update(&ctx, (const unsigned char*)this->error_code, this->error_code_totalLength_nothsVal);
	}
	if (this->unknown_attribute) {
		HMAC_Update(&ctx, (const unsigned char*)this->unknown_attribute, this->unknown_attribute_totalLength_nothsVal);
	}

	if (this->software) {
		HMAC_Update(&ctx, (const unsigned char*)this->software, this->software_totalLength_nothsVal);
	}
	if (this->channel_number) {
		HMAC_Update(&ctx, (const unsigned char*)this->channel_number, this->channel_number_totalLength_nothsVal);
	}
	if (this->lifetime) {
		HMAC_Update(&ctx, (const unsigned char*)this->lifetime, this->lifetime_totalLength_nothsVal);
	}
	if (this->peer_addr) {
		HMAC_Update(&ctx, (const unsigned char*)this->peer_addr, this->peer_addr_totalLength_nothsVal);
	}
	if (this->data) {
		HMAC_Update(&ctx, (const unsigned char*)this->data, this->data_totalLength_nothsVal);
	}
	if (this->relayed_addr) {
		HMAC_Update(&ctx, (const unsigned char*)this->relayed_addr, this->relayed_addr_totalLength_nothsVal);
	}
	if (this->even_port) {
		HMAC_Update(&ctx, (const unsigned char*)this->even_port, this->even_port_totalLength_nothsVal);
	}
	if (this->requested_transport) {
		HMAC_Update(&ctx, (const unsigned char*)this->requested_transport, this->requested_transport_totalLength_nothsVal);
	}
	if (this->dont_fragment) {
		HMAC_Update(&ctx, (const unsigned char*)this->dont_fragment, this->dont_fragment_totalLength_nothsVal);
	}
	if (this->reservation_token) {
		HMAC_Update(&ctx, (const unsigned char*)this->reservation_token, this->reservation_token_totalLength_nothsVal);
	}
	if (this->requested_addr_family) {
		HMAC_Update(&ctx, (const unsigned char*)this->requested_addr_family, this->requested_addr_family_totalLength_nothsVal);
	}
	if (this->connection_id) {
		HMAC_Update(&ctx, (const unsigned char*)this->connection_id, this->connection_id_totalLength_nothsVal);
	}

	HMAC_Final(&ctx, this->message_integrity->turn_attr_hmac, &md_len); /* HMAC-SHA1 is 20 bytes length */
	HMAC_CTX_cleanup(&ctx);
	return 1;
}

unsigned char* StunProtocol::turn_calculate_integrity_hmac(const unsigned char* buf, unsigned char* userAcountHashkey)
{
	SHAmethod shamethod(this->message_integrity);
	size_t	keysize = shamethod.get_hmackey_size();
	size_t message_integrity_size = ntohs(this->message_integrity->turn_attr_len);

	size_t bufferdatalen = 0;
	if (this->fingerprint)
	{
		bufferdatalen = this->getRequestLength() - sizeof(struct turn_attr_fingerprint) - sizeof(struct turn_attr_message_integrity);
	}
	else
	{
		bufferdatalen = this->getRequestLength() - sizeof(struct turn_attr_message_integrity);
	}

	unsigned char integrity[message_integrity_size];
	HMAC_CTX ctx;
	/* MESSAGE-INTEGRITY uses HMAC-SHA1 */
	HMAC_CTX_init(&ctx);
	HMAC_Init(&ctx, userAcountHashkey, keysize, EVP_sha1());
	HMAC_Update(&ctx, buf, bufferdatalen);

	HMAC_Final(&ctx, integrity, &message_integrity_size); /* HMAC-SHA1 is 20 bytes length */
	HMAC_CTX_cleanup(&ctx);
	return integrity;
}

void  StunProtocol::turn_msg_refresh_response_create(const uint8_t * transactionID)
{
	this->turn_msg_create(TURN_METHOD_REFRESH, STUN_SUCCESS_RESP, 0, transactionID);
}

void  StunProtocol::turn_attr_lifetime_create(uint32_t lifetime)
{
	this->lifetime = (struct turn_attr_lifetime*)malloc(sizeof(struct turn_attr_lifetime));
	if (this->lifetime == NULL) {
		return;
	}
	this->lifetime->turn_attr_type = htons(TURN_ATTR_LIFETIME);
	this->lifetime->turn_attr_len = htons(4);
	this->lifetime->turn_attr_lifetime = htonl(lifetime);
}

//创建回复的消息头
int StunProtocol::turn_msg_create(uint16_t requestMethod, uint16_t responseType, uint16_t messagelen, const uint8_t * transactionID)
{
	this->reuqestHeader = (struct turn_msg_hdr*)malloc(sizeof(struct turn_msg_hdr));
	if (this->reuqestHeader == NULL) {
		return -1;
	}
	this->reuqestHeader->turn_msg_type = htons(requestMethod | responseType);
	this->reuqestHeader->turn_msg_len = htons(messagelen);
	this->reuqestHeader->turn_msg_cookie = htonl(STUN_MAGIC_COOKIE);
	memcpy(this->reuqestHeader->turn_msg_id, transactionID, 12);
	this->reuqestHeader_totalLength_nothsVal = sizeof(struct turn_msg_hdr);
	//消息头不需要调用addHeaderMsgLength方法
	return 1;
}


int  StunProtocol::turn_attr_connection_id_create(uint32_t id)
{
	this->connection_id = (struct turn_attr_connection_id*)malloc(sizeof(struct turn_attr_connection_id));
	if (this->connection_id == NULL) {
		return -1;
	}
	this->connection_id->turn_attr_type = htons(TURN_ATTR_CONNECTION_ID);
	this->connection_id->turn_attr_len = htons(4);
	this->connection_id->turn_attr_id = id;
	this->connection_id_totalLength_nothsVal = sizeof(struct turn_attr_connection_id);
	this->addHeaderMsgLength(this->connection_id_totalLength_nothsVal);
	return 1;
}
void  StunProtocol::turn_msg_connectionbind_response_create(const uint8_t * id)
{
	this->turn_msg_create(TURN_METHOD_CONNECTIONBIND, STUN_SUCCESS_RESP, 0, id);
}

int  StunProtocol::turn_msg_allocate_response_create(const uint8_t * id)
{
	return this->turn_msg_create(TURN_METHOD_ALLOCATE, STUN_SUCCESS_RESP, 0, id);
}

int StunProtocol::turn_attr_realm_create(const char* realm)
{
	size_t realmlen = strlen(realm);
	size_t real_len = realmlen;
	/* realm can be as long as 763 bytes */
	if (realmlen > 763)
	{
		return NULL;
	}
	/* real_len, attribute header size and padding must be a multiple of four */
	if ((real_len + 4) % 4)
	{
		real_len += (4 - (real_len % 4));
	}

	this->realm = (struct turn_attr_realm*)malloc(sizeof(struct turn_attr_realm) + real_len);
	this->realm->turn_attr_type = htons(STUN_ATTR_REALM);
	this->realm->turn_attr_len = htons(realmlen);
	memset(this->realm->turn_attr_realm, 0x00, real_len);
	memcpy(this->realm->turn_attr_realm, realm, realmlen);
	this->realm_totalLength_nothsVal = sizeof(struct turn_attr_realm) + real_len;
	this->addHeaderMsgLength(this->realm_totalLength_nothsVal);
	return 1;
}
//创建错误消息
int  StunProtocol::turn_attr_error_create(uint16_t code, const char* reason)
{
	size_t reasonsize = sizeof(reason);

	uint8_t _class = code / 100;
	uint8_t number = code % 100;
	size_t real_len = reasonsize;

	/* reason can be as long as 763 bytes */
	if (reasonsize > 763)
	{
		return -1;
	}

	/* class MUST be between 3 and 6 */
	if (_class < 3 || _class > 6)
	{
		return -1;
	}

	/* number MUST be between 0 and 99 */
	if (number > 99)
	{
		return -1;
	}
	/* real_len, attribute header size and padding must be a multiple of four */
	if ((real_len + 4) % 4)
	{
		real_len += (4 - (real_len % 4));
	}

	this->error_code = (struct turn_attr_error_code*)malloc(sizeof(struct turn_attr_error_code) + real_len);
	if (this->error_code == NULL) {
		return -1;
	}
	this->error_code->turn_attr_type = htons(STUN_ATTR_ERROR_CODE);
	this->error_code->turn_attr_len = htons(4 + real_len);

	if (is_little_endian())
	{
		this->error_code->turn_attr_reserved_class = _class << 16;
	}
	else /* big endian */
	{
		this->error_code->turn_attr_reserved_class = _class;
	}
	this->error_code->turn_attr_number = number;
	/* even if strlen(reason) < len, strncpy will add extra-zero
	 * also no need to add final NULL character since length is known (TLV)
	 */
	strncpy((char*)this->error_code->turn_attr_reason, reason, real_len);
	//增加协议头中的长度
	this->error_code_totalLength_nothsVal = sizeof(struct turn_attr_error_code) + real_len;
	this->addHeaderMsgLength(this->error_code_totalLength_nothsVal);
	return 1;
}

//创建随机数消息
int  StunProtocol::turn_attr_nonce_create(const uint8_t * nonce)
{
	size_t nonceSize = 48;
	size_t real_len = nonceSize;
	/* nonce can be as long as 763 bytes */
	if (nonceSize > 763)
	{
		return NULL;
	}
	/* real_len, attribute header size and padding must be a multiple of four */
	if ((real_len + 4) % 4)
	{
		real_len += (4 - (real_len % 4));
	}

	this->nonce = (struct turn_attr_nonce*)malloc(sizeof(struct turn_attr_nonce) + real_len);
	if (this->nonce == NULL) {
		return -1;
	}


	this->nonce->turn_attr_type = htons(STUN_ATTR_NONCE);
	this->nonce->turn_attr_len = htons(nonceSize);
	memset(this->nonce->turn_attr_nonce, 0x00, real_len);
	memcpy(this->nonce->turn_attr_nonce, nonce, nonceSize);

	this->nonce_totalLength_nothsVal = sizeof(struct turn_attr_nonce) + real_len;
	this->addHeaderMsgLength(this->nonce_totalLength_nothsVal);
	return 1;
}

int  StunProtocol::turn_attr_fingerprint_create(uint32_t fingerprint)
{
	this->fingerprint = (struct turn_attr_fingerprint*)malloc(sizeof(struct turn_attr_fingerprint));
	if (this->fingerprint == NULL) {
		return -1;
	}

	this->fingerprint->turn_attr_type = htons(STUN_ATTR_FINGERPRINT);
	this->fingerprint->turn_attr_len = htons(4);
	this->fingerprint->turn_attr_crc = htonl(fingerprint);

	this->fingerprint_totalLength_nothsVal = sizeof(struct turn_attr_fingerprint);
	this->addHeaderMsgLength(this->fingerprint_totalLength_nothsVal);

	/* do not take into account the attribute itself */
	this->fingerprint->turn_attr_crc = htonl(turn_calculate_fingerprint());
	this->fingerprint->turn_attr_crc ^= htonl(STUN_FINGERPRINT_XOR_VALUE);
	return 1;
}
//计算整个消息的C32值，确定消息的唯一性
uint32_t StunProtocol::turn_calculate_fingerprint()
{
	uint32_t crc = 0;
	if (this->reuqestHeader) {

		crc = crc32_generate((uint8_t*)this->reuqestHeader, this->reuqestHeader_totalLength_nothsVal, crc);
	}
	if (this->mapped_addr) {

		crc = crc32_generate((uint8_t*)this->mapped_addr, this->mapped_addr_totalLength_nothsVal, crc);
	}
	if (this->xor_mapped_addr) {

		crc = crc32_generate((uint8_t*)this->xor_mapped_addr, this->xor_mapped_addr_totalLength_nothsVal, crc);
	}
	if (this->alternate_server) {

		crc = crc32_generate((uint8_t*)this->alternate_server, this->alternate_server_totalLength_nothsVal, crc);
	}
	if (this->nonce) {

		crc = crc32_generate((uint8_t*)this->nonce, this->nonce_totalLength_nothsVal, crc);
	}
	if (this->realm) {

		crc = crc32_generate((uint8_t*)this->realm, this->realm_totalLength_nothsVal, crc);
	}
	if (this->username) {

		crc = crc32_generate((uint8_t*)this->username, this->username_totalLength_nothsVal, crc);
	}
	if (this->error_code) {

		crc = crc32_generate((uint8_t*)this->error_code, this->error_code_totalLength_nothsVal, crc);
	}
	if (this->unknown_attribute) {

		crc = crc32_generate((uint8_t*)this->unknown_attribute, this->unknown_attribute_totalLength_nothsVal, crc);
	}
	if (this->message_integrity) {

		crc = crc32_generate((uint8_t*)this->message_integrity, this->message_integrity_totalLength_nothsVal, crc);
	}
	if (this->software) {

		crc = crc32_generate((uint8_t*)this->software, this->software_totalLength_nothsVal, crc);
	}
	if (this->channel_number) {

		crc = crc32_generate((uint8_t*)this->channel_number, this->channel_number_totalLength_nothsVal, crc);
	}
	if (this->lifetime) {

		crc = crc32_generate((uint8_t*)this->lifetime, this->lifetime_totalLength_nothsVal, crc);
	}
	if (this->peer_addr) {

		crc = crc32_generate((uint8_t*)this->peer_addr, this->peer_addr_totalLength_nothsVal, crc);
	}
	if (this->data) {

		crc = crc32_generate((uint8_t*)this->data, this->data_totalLength_nothsVal, crc);
	}
	if (this->relayed_addr) {

		crc = crc32_generate((uint8_t*)this->relayed_addr, this->relayed_addr_totalLength_nothsVal, crc);
	}
	if (this->even_port) {

		crc = crc32_generate((uint8_t*)this->even_port, this->even_port_totalLength_nothsVal, crc);
	}
	if (this->requested_transport) {

		crc = crc32_generate((uint8_t*)this->requested_transport, this->requested_transport_totalLength_nothsVal, crc);
	}
	if (this->dont_fragment) {

		crc = crc32_generate((uint8_t*)this->dont_fragment, this->dont_fragment_totalLength_nothsVal, crc);
	}
	if (this->reservation_token) {

		crc = crc32_generate((uint8_t*)this->reservation_token, this->reservation_token_totalLength_nothsVal, crc);
	}
	if (this->requested_addr_family) {

		crc = crc32_generate((uint8_t*)this->requested_addr_family, this->requested_addr_family_totalLength_nothsVal, crc);
	}

	if (this->connection_id) {

		crc = crc32_generate((uint8_t*)this->connection_id, this->connection_id_totalLength_nothsVal, crc);
	}
	return crc;
}

//48字节长度的随机数
uint8_t* StunProtocol::turn_generate_nonce(const char* noncekey)
{
	size_t len = 48;
	uint8_t* nonce = (uint8_t*)malloc(len);
	size_t noncekey_len = strlen(noncekey);

	time_t t;
	char c = ':';
	MD5_CTX ctx;
	unsigned char md_buf[MD5_DIGEST_LENGTH];
	if (len < (16 + MD5_DIGEST_LENGTH))
	{
		return NULL;
	}
	MD5_Init(&ctx);
	/* timestamp */
	t = time(NULL);
	/* add expire period */
	t += TURN_DEFAULT_NONCE_LIFETIME;

	t = (time_t)htonl((uint32_t)t);
	hex_convert((unsigned char*)& t, sizeof(time_t), nonce, sizeof(time_t) * 2);

	if (sizeof(time_t) == 4) /* 32 bit */
	{
		memset(nonce + 8, 0x30, 8);
	}

	MD5_Update(&ctx, nonce, 16); /* time */
	MD5_Update(&ctx, &c, 1);
	MD5_Update(&ctx, noncekey, noncekey_len);
	MD5_Final(md_buf, &ctx);
	/* add MD5 at the end of the nonce */
	hex_convert(md_buf, MD5_DIGEST_LENGTH, nonce + 16, len - 16);
	return nonce;
}


int StunProtocol::turn_xor_address_cookie(int family, uint8_t * peer_addr, uint16_t * peer_port, const uint8_t * cookie, const uint8_t * msg_id)
{
	size_t i = 0;
	size_t len = 0;

	switch (family)
	{
	case STUN_ATTR_FAMILY_IPV4:
		len = 4;
		break;
	case STUN_ATTR_FAMILY_IPV6:
		len = 16;
		break;
	default:
		return -1;
	}

	/* XOR port */
	*peer_port ^= ((cookie[0] << 8) | (cookie[1]));

	/* IPv4/IPv6 XOR cookie (just the first four bytes of IPv6 address) */
	for (i = 0; i < 4; i++)
	{
		peer_addr[i] ^= cookie[i];
	}

	/* end of IPv6 address XOR transaction ID */
	for (i = 4; i < len; i++)
	{
		peer_addr[i] ^= msg_id[i - 4];
	}

	return 0;
}


char* StunProtocol::getMessageData()
{
	auto requestLength = this->getRequestLength();
	char* resultBuffer = (char*)malloc(requestLength);
	const char* oldBufferPtr = resultBuffer;

	size_t totallength = 0;

	if (this->reuqestHeader) {
		memcpy(resultBuffer, this->reuqestHeader, this->reuqestHeader_totalLength_nothsVal);
		resultBuffer += this->reuqestHeader_totalLength_nothsVal;
		totallength += this->reuqestHeader_totalLength_nothsVal;
	}
	if (this->mapped_addr) {
		memcpy(resultBuffer, this->mapped_addr, this->mapped_addr_totalLength_nothsVal);
		resultBuffer += this->mapped_addr_totalLength_nothsVal;
		totallength += this->mapped_addr_totalLength_nothsVal;
	}

	if (this->xor_mapped_addr) {
		memcpy(resultBuffer, this->xor_mapped_addr, this->xor_mapped_addr_totalLength_nothsVal);
		resultBuffer += this->xor_mapped_addr_totalLength_nothsVal;
		totallength += this->xor_mapped_addr_totalLength_nothsVal;
	}

	if (this->alternate_server) {
		memcpy(resultBuffer, this->alternate_server, this->alternate_server_totalLength_nothsVal);
		resultBuffer += this->alternate_server_totalLength_nothsVal;
		totallength += this->alternate_server_totalLength_nothsVal;
	}

	if (this->nonce) {
		memcpy(resultBuffer, this->nonce, this->nonce_totalLength_nothsVal);
		resultBuffer += this->nonce_totalLength_nothsVal;
		totallength += this->nonce_totalLength_nothsVal;
	}

	if (this->realm) {
		memcpy(resultBuffer, this->realm, this->realm_totalLength_nothsVal);
		resultBuffer += this->realm_totalLength_nothsVal;
		totallength += this->realm_totalLength_nothsVal;
	}

	if (this->username) {
		memcpy(resultBuffer, this->username, this->username_totalLength_nothsVal);
		resultBuffer += this->username_totalLength_nothsVal;
		totallength += this->username_totalLength_nothsVal;
	}

	if (this->error_code) {
		memcpy(resultBuffer, this->error_code, this->error_code_totalLength_nothsVal);
		resultBuffer += this->error_code_totalLength_nothsVal;
		totallength += this->error_code_totalLength_nothsVal;
	}

	if (this->unknown_attribute) {
		memcpy(resultBuffer, this->unknown_attribute, this->unknown_attribute_totalLength_nothsVal);
		resultBuffer += this->unknown_attribute_totalLength_nothsVal;
		totallength += this->unknown_attribute_totalLength_nothsVal;
	}

	if (this->software) {
		memcpy(resultBuffer, this->software, this->software_totalLength_nothsVal);
		resultBuffer += this->software_totalLength_nothsVal;
		totallength += this->software_totalLength_nothsVal;
	}

	if (this->channel_number) {
		memcpy(resultBuffer, this->channel_number, this->channel_number_totalLength_nothsVal);
		resultBuffer += this->channel_number_totalLength_nothsVal;
		totallength += this->channel_number_totalLength_nothsVal;
	}

	if (this->lifetime) {
		memcpy(resultBuffer, this->lifetime, this->lifetime_totalLength_nothsVal);
		resultBuffer += this->lifetime_totalLength_nothsVal;
		totallength += this->lifetime_totalLength_nothsVal;
	}

	if (this->peer_addr) {
		memcpy(resultBuffer, this->peer_addr, this->peer_addr_totalLength_nothsVal);
		resultBuffer += this->peer_addr_totalLength_nothsVal;
		totallength += this->peer_addr_totalLength_nothsVal;
	}

	if (this->data) {
		memcpy(resultBuffer, this->data, this->data_totalLength_nothsVal);
		resultBuffer += this->data_totalLength_nothsVal;
		totallength += this->data_totalLength_nothsVal;
	}

	if (this->relayed_addr) {
		memcpy(resultBuffer, this->relayed_addr, this->relayed_addr_totalLength_nothsVal);
		resultBuffer += this->relayed_addr_totalLength_nothsVal;
		totallength += this->relayed_addr_totalLength_nothsVal;
	}

	if (this->even_port) {
		memcpy(resultBuffer, this->even_port, this->even_port_totalLength_nothsVal);
		resultBuffer += this->even_port_totalLength_nothsVal;
		totallength += this->even_port_totalLength_nothsVal;
	}

	if (this->requested_transport) {
		memcpy(resultBuffer, this->requested_transport, this->requested_transport_totalLength_nothsVal);
		resultBuffer += this->requested_transport_totalLength_nothsVal;
		totallength += this->requested_transport_totalLength_nothsVal;
	}

	if (this->dont_fragment) {
		memcpy(resultBuffer, this->dont_fragment, this->dont_fragment_totalLength_nothsVal);
		resultBuffer += this->dont_fragment_totalLength_nothsVal;
		totallength += this->dont_fragment_totalLength_nothsVal;
	}

	if (this->reservation_token) {
		memcpy(resultBuffer, this->reservation_token, this->reservation_token_totalLength_nothsVal);
		resultBuffer += this->reservation_token_totalLength_nothsVal;
		totallength += this->reservation_token_totalLength_nothsVal;
	}

	if (this->requested_addr_family) {
		memcpy(resultBuffer, this->requested_addr_family, this->requested_addr_family_totalLength_nothsVal);
		resultBuffer += this->requested_addr_family_totalLength_nothsVal;
		totallength += this->requested_addr_family_totalLength_nothsVal;
	}

	if (this->connection_id) {
		memcpy(resultBuffer, this->connection_id, this->connection_id_totalLength_nothsVal);
		resultBuffer += this->connection_id_totalLength_nothsVal;
		totallength += this->connection_id_totalLength_nothsVal;
	}

	if (this->message_integrity) {
		memcpy(resultBuffer, this->message_integrity, this->message_integrity_totalLength_nothsVal);
		resultBuffer += this->message_integrity_totalLength_nothsVal;
		totallength += this->message_integrity_totalLength_nothsVal;
	}

	if (this->fingerprint) {
		memcpy(resultBuffer, this->fingerprint, this->fingerprint_totalLength_nothsVal);
		resultBuffer += this->fingerprint_totalLength_nothsVal;
		totallength += this->fingerprint_totalLength_nothsVal;
	}

	if (requestLength != totallength)
	{
		//debug(DBG_ATTR, "发生错误了\n");
	}
	return (char*)oldBufferPtr;
}



account_desc* StunProtocol::account_desc_new(const char* username, const char* password, const char* realm, enum account_state state)
{
	struct account_desc* ret = NULL;

	if (!username || !password || !realm)
	{
		return NULL;
	}

	if (!(ret = (struct account_desc*)malloc(sizeof(struct account_desc))))
	{
		return NULL;
	}

	/* copy username and realm */
	strncpy(ret->username, username, sizeof(ret->username) - 1);
	ret->username[sizeof(ret->username) - 1] = 0x00;
	strncpy(ret->realm, realm, sizeof(ret->realm) - 1);
	ret->realm[sizeof(ret->realm) - 1] = 0x00;

	/* set state */
	ret->state = state;
	ret->allocations = 0;
	ret->is_tmp = 0;

	this->turn_calculate_authentication_key(username, realm, password, ret->key, sizeof(ret->key));

	return ret;
}


int StunProtocol::turn_calculate_authentication_key(const char* username, const char* realm, const char* password, unsigned char* key, size_t key_len)
{
	MD5_CTX ctx;
	if (key_len < 16)
	{
		return -1;
	}

	MD5_Init(&ctx);
	MD5_Update(&ctx, username, strlen(username));
	MD5_Update(&ctx, ":", 1);
	MD5_Update(&ctx, realm, strlen(realm));
	MD5_Update(&ctx, ":", 1);
	MD5_Update(&ctx, password, strlen(password));
	MD5_Final(key, &ctx);

	return 0;
}

#pragma endregion

StunProtocol::~StunProtocol()
{
}




