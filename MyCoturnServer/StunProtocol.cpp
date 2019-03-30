#include "StunProtocol.h"

#define STUN_HEADER_LENGTH (20)
int turn_tcp = 1;


StunProtocol::StunProtocol()
{
}


#pragma region 解析协议的方法
size_t unknown_idx = 0;
/* count of XOR-PEER-ADDRESS attribute */
size_t xor_peer_address_nb = 0;
StunProtocol::StunProtocol(buffer_type data, int length)
{
	if (length < 20) {
		return;
	}
	char* allBuffer = data;
	//获取消息类型，它在前0-1字节 
	memcpy(&reuqestHeader->turn_msg_type, allBuffer, 2);
	allBuffer += 2;
	//获取消息长度，它在前2-3字节
	memcpy(&reuqestHeader->turn_msg_len, allBuffer, 2);
	allBuffer += 2;
	//获取magic_cookie，它在4-7字节 
	memcpy(&reuqestHeader->turn_msg_cookie, allBuffer, 4);
	allBuffer += 4;
	//获取transactionID，它在8-19字节
	memcpy(&reuqestHeader->turn_msg_id, allBuffer, 12);
	allBuffer += 12;

	int startArrIndex = 20;
	while (startArrIndex < length)
	{
		uint16_t attr_type;
		//获取attribute type
		memcpy(&attr_type, allBuffer, 2);
		getAttr(allBuffer, attr_type);
		allBuffer += 2;
		startArrIndex += 2;

		//获取attribute length
		uint16_t attr_len;
		memcpy(&attr_len, allBuffer, 2);
		allBuffer += 2;
		startArrIndex += 2;
		if (fingerprint)
		{
			/* when present, the FINGERPRINT attribute MUST be the last attribute */
			/* ignore other message
			 */
			return;
		}
		/* MESSAGE-INTEGRITY is the last attribute except if FINGERPRINT follow
		 * it
		 */
		if (message_integrity && ntohs(attr_type) != STUN_ATTR_FINGERPRINT)
		{
			/* with the exception of the FINGERPRINT attribute [...]
			 * agents MUST ignore all other attributes that follow MESSAGE-INTEGRITY
			 */
			return;
		}
		allBuffer += ntohs(attr_len);
		startArrIndex += ntohs(attr_len);
	}
	unknown_size = unknown_idx;
}
//获取协议里的attribute
int StunProtocol::getAttr(const char* bufferPtr, uint16_t attrtype)
{
	switch (ntohs(attrtype))
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
		if (ntohs(attrtype) <= 0x7fff)
		{
			/* comprehension-required attribute but server does not understand
			 * it
			 */
			if (!unknown_size)
			{
				break;
			}
			unknown[unknown_idx] = htons(attrtype);
			unknown_size--;
			unknown_idx++;
		}
		break;
	}

	return 0;
}
#pragma endregion


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
bool StunProtocol::IsErrorRequest()
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
	if (fingerprint)
	{
		/* verify if CRC is valid */
		uint32_t crc = 0;
		crc = crc32_generate((const unsigned char*)data, getRequestLength() - sizeof(struct turn_attr_fingerprint), 0);
		if (htonl(crc) != (fingerprint->turn_attr_crc ^ htonl(STUN_FINGERPRINT_XOR_VALUE)))
		{
			debug(DBG_ATTR, "Fingerprint mismatch\n");
			return true;
		}
	}

	return false;
}

///根据nonce_key 生成一个随机数
unsigned char* StunProtocol::get_generate_nonce(char* key, size_t key_len)
{
	unsigned char * result;
	time_t t;
	char c = ':';
	MD5_CTX ctx;
	unsigned char md_buf[MD5_DIGEST_LENGTH];

	MD5_Init(&ctx);

	/* timestamp */
	t = time(NULL);

	/* add expire period */
	t += TURN_DEFAULT_NONCE_LIFETIME;

	t = (time_t)htonl((uint32_t)t);
	hex_convert((unsigned char*)&t, sizeof(time_t), result, sizeof(time_t) * 2);
	if (sizeof(time_t) == 4) /* 32 bit */
	{
		memset(result + 8, 0x30, 8);
	}

	MD5_Update(&ctx, result, 16); /* time */
	MD5_Update(&ctx, &c, 1);
	MD5_Update(&ctx, key, key_len);
	MD5_Final(md_buf, &ctx);

	/* add MD5 at the end of the nonce */
	hex_convert(md_buf, MD5_DIGEST_LENGTH, result + 16, 32);

	return result;
}

void  StunProtocol::create_error_response_401(uint16_t requestMethod, const uint8_t* transactionID, char* realmstr, unsigned char* nonce)
{
	this->turn_msg_create(requestMethod, STUN_ERROR_RESP, 0, transactionID);
	this->turn_attr_error_create(401, STUN_ERROR_401);
	this->turn_attr_realm_create(realmstr);
	this->turn_attr_nonce_create((const uint8_t*)nonce);
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

	this->software->turn_attr_type = htons(STUN_ATTR_SOFTWARE);
	this->software->turn_attr_len = htons(softwareSize);
	memset(this->software->turn_attr_software, 0x00, real_len);
	memcpy(this->software->turn_attr_software, software, softwareSize);
	return 1;
}


//创建回复的消息头
void  StunProtocol::turn_msg_create(uint16_t requestMethod, uint16_t responseType, uint16_t messagelen, const uint8_t* transactionID)
{
	this->reuqestHeader->turn_msg_type = htons(requestMethod | responseType);
	this->reuqestHeader->turn_msg_len = htons(messagelen);
	this->reuqestHeader->turn_msg_cookie = htonl(STUN_MAGIC_COOKIE);
	memcpy(this->reuqestHeader->turn_msg_id, transactionID, 12);
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
	this->realm->turn_attr_type = htons(STUN_ATTR_REALM);
	this->realm->turn_attr_len = htons(realmlen);
	memset(this->realm->turn_attr_realm, 0x00, real_len);
	memcpy(this->realm->turn_attr_realm, realm, realmlen);
	return 1;
}

//创建错误消息
int  StunProtocol::turn_attr_error_create(uint16_t code, const char* reason)
{
	size_t reasonsize = sizeof(reason);

	this->error_code = NULL;
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
	return 1;
}

//创建随机数消息
int  StunProtocol::turn_attr_nonce_create(const uint8_t* nonce)
{
	size_t nonceSize = sizeof(nonce);
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
	this->nonce->turn_attr_type = htons(STUN_ATTR_NONCE);
	this->nonce->turn_attr_len = htons(nonceSize);
	memset(this->nonce->turn_attr_nonce, 0x00, real_len);
	memcpy(this->nonce->turn_attr_nonce, nonce, nonceSize);
	return 1;
}

int  StunProtocol::turn_attr_fingerprint_create(uint32_t fingerprint)
{
	this->fingerprint->turn_attr_type = htons(STUN_ATTR_FINGERPRINT);
	this->fingerprint->turn_attr_len = htons(4);
	this->fingerprint->turn_attr_crc = htonl(fingerprint);
	/* do not take into account the attribute itself */
	this->fingerprint->turn_attr_crc = htonl(turn_calculate_fingerprint();
	this->fingerprint->turn_attr_crc ^= htonl(STUN_FINGERPRINT_XOR_VALUE);
	return 1;
}
//计算整个消息的C32值，确定消息的唯一性
uint32_t StunProtocol::turn_calculate_fingerprint()
{
	uint32_t crc = 0;
	if (this->reuqestHeader) {
		计算长度不好弄，因为有动态数组
		crc = crc32_generate((uint8_t*)this->reuqestHeader, sizeof(this->reuqestHeader), crc);
	}



	return crc;
}
#pragma endregion



StunProtocol::~StunProtocol()
{
}




