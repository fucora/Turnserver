#include "StunProtocol.h"

#define STUN_HEADER_LENGTH (20)
int turn_tcp = 1;


#pragma region 原始协议
uint16_t requestType_Original;
uint16_t requestLength_Original;
uint32_t magic_cookie;
char transactionID_Original[12];

uint16_t* unknown;
size_t unknown_size;
turn_attr_mapped_address* mapped_addr; /**< MAPPED-ADDRESS attribute */
turn_attr_xor_mapped_address* xor_mapped_addr; /**< XOR-MAPPED-ADDRESS attribute */
turn_attr_alternate_server* alternate_server; /**< ALTERNATE-SERVER attribute */
turn_attr_nonce* nonce; /**< NONCE attribute */
turn_attr_realm* realm; /**< REALM attribute */
turn_attr_username* username; /**< USERNAME attribute */
turn_attr_error_code* error_code; /**< ERROR-CODE attribute */
turn_attr_unknown_attribute* unknown_attribute; /**< UNKNOWN-ATTRIBUTE attribute */
turn_attr_message_integrity* message_integrity; /**< MESSAGE-INTEGRITY attribute */
turn_attr_fingerprint* fingerprint; /**< FINGERPRINT attribute */
turn_attr_software* software; /**< SOFTWARE attribute */
turn_attr_channel_number* channel_number; /**< CHANNEL-NUMBER attribute */
turn_attr_lifetime* lifetime; /**< LIFETIME attribute */
turn_attr_xor_peer_address* peer_addr[XOR_PEER_ADDRESS_MAX]; /**< XOR-PEER-ADDRESS attribute */
turn_attr_data* data; /**< DATA attribute */
turn_attr_xor_relayed_address* relayed_addr; /**< XOR-RELAYED-ADDRESS attribute */
turn_attr_even_port* even_port; /**< REQUESTED-PROPS attribute */
turn_attr_requested_transport* requested_transport; /**< REQUESTED-TRANSPORT attribute */
turn_attr_dont_fragment* dont_fragment; /**< DONT-FRAGMENT attribute */
turn_attr_reservation_token* reservation_token; /**< RESERVATION-TOKEN attribute */
turn_attr_requested_address_family* requested_addr_family; /**< REQUESTED-ADDRESS-FAMILY attribute (RFC6156) */
turn_attr_connection_id* connection_id; /**< CONNECTION-ID attribute (RFC6062) */
size_t xor_peer_addr_overflow; /**< If set to 1, not all the XOR-PEER-ADDRESS given in request are in this structure */
#pragma endregion


#pragma region 解析协议
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
	memcpy(&requestType_Original, allBuffer, 2);
	allBuffer += 2;
	//获取消息长度，它在前2-3字节
	memcpy(&requestLength_Original, allBuffer, 2);
	allBuffer += 2;
	//获取magic_cookie，它在4-7字节 
	memcpy(&magic_cookie, allBuffer, 4);
	allBuffer += 4;
	//获取transactionID，它在8-19字节
	memcpy(&transactionID_Original, allBuffer, 12);
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
	return TURN_IS_CHANNELDATA(requestType_Original);
}
//获取请求类型，REQUEST，INDICATION,SUCCESS_RESP,ERROR_RESP
uint16_t StunProtocol::getRequestType()
{
	return ntohs(requestType_Original);
}
//获取请求的消息总长度
uint16_t StunProtocol::getRequestLength()
{
	return	ntohs(requestLength_Original) + STUN_HEADER_LENGTH;
}

uint16_t StunProtocol::getRequestMethod()
{
	auto requesttype = getRequestType();
	return STUN_GET_METHOD(requesttype);
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
	auto requestType = getRequestType();
	if (!STUN_IS_REQUEST(requestType) &&!STUN_IS_INDICATION(requestType) &&!STUN_IS_SUCCESS_RESP(requestType) &&!STUN_IS_ERROR_RESP(requestType))
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
	if (magic_cookie != htonl(STUN_MAGIC_COOKIE))
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

#pragma endregion

StunProtocol::~StunProtocol()
{
}




