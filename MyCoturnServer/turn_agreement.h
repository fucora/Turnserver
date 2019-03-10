#pragma once

#include "commonTypes.h"


typedef const void* stun_attr_ref;
static void generate_random_nonce(unsigned char *nonce, std::size_t sz);

#define	u08bits char;
#define	s08bits	char
#define	u16bits uint16_t
 
#define	u32bits	std::uint32_t
#define	u64bits	std::uint64_t

#define STUN_VALID_CHANNEL(chn) ((chn)>=0x4000 && (chn)<=0x7FFF)

#define STUN_ATTRIBUTE_FINGERPRINT (0x8028)
#define STUN_METHOD_BINDING (0x0001)
#define CRC_MASK    0xFFFFFFFFUL 

#define STUN_METHOD_BINDING (0x0001)
#define STUN_METHOD_ALLOCATE (0x0003)
#define STUN_METHOD_REFRESH (0x0004)
#define STUN_METHOD_SEND (0x0006)
#define STUN_METHOD_DATA (0x0007)
#define STUN_METHOD_CREATE_PERMISSION (0x0008)
#define STUN_METHOD_CHANNEL_BIND (0x0009)
/* RFC 6062 ==>>*/
#define STUN_METHOD_CONNECT (0x000a)
#define STUN_METHOD_CONNECTION_BIND (0x000b)
#define STUN_METHOD_CONNECTION_ATTEMPT (0x000c)
///////////
#define STUN_ATTRIBUTE_ERROR_CODE (0x0009)
#define STUN_ATTRIBUTE_REALM (0x0014)
#define STUN_ATTRIBUTE_NONCE (0x0015)
#define STUN_ATTRIBUTE_THIRD_PARTY_AUTHORIZATION (0x802E)

#define STUN_DEFAULT_ALLOCATE_LIFETIME (600)
#define STUN_MIN_ALLOCATE_LIFETIME STUN_DEFAULT_ALLOCATE_LIFETIME
/* RFC 6156 ==>> */
#define STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV4 (0x01)
#define STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6 (0x02)
#define STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_DEFAULT (0x00)
#define STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_INVALID (-1)

///////////////
#define STUN_ATTRIBUTE_MAPPED_ADDRESS (0x0001)
#define STUN_ATTRIBUTE_MOBILITY_TICKET (0x8030)
#define STUN_ATTRIBUTE_REQUESTED_TRANSPORT (0x0019)
#define STUN_ATTRIBUTE_CHANNEL_NUMBER (0x000C)
#define STUN_ATTRIBUTE_LIFETIME (0x000D)
#define STUN_ATTRIBUTE_BANDWIDTH (0x0010)
#define STUN_ATTRIBUTE_XOR_PEER_ADDRESS (0x0012)
#define STUN_ATTRIBUTE_DATA (0x0013)
#define STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS (0x0016)
#define STUN_ATTRIBUTE_EVEN_PORT (0x0018)
#define STUN_ATTRIBUTE_REQUESTED_TRANSPORT (0x0019)
#define STUN_ATTRIBUTE_DONT_FRAGMENT (0x001A)
#define STUN_ATTRIBUTE_TIMER_VAL (0x0021)
#define STUN_ATTRIBUTE_RESERVATION_TOKEN (0x0022)
#define STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY (0x0017)
#define STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS (0x0020)
#define STUN_ATTRIBUTE_ALTERNATE_SERVER (0x8023)
#define OLD_STUN_ATTRIBUTE_RESPONSE_ADDRESS (0x0002)
#define OLD_STUN_ATTRIBUTE_SOURCE_ADDRESS (0x0004)
#define OLD_STUN_ATTRIBUTE_CHANGED_ADDRESS (0x0005)
#define OLD_STUN_ATTRIBUTE_REFLECTED_FROM (0x000B)
#define STUN_ATTRIBUTE_RESPONSE_ORIGIN (0x802B)
#define STUN_ATTRIBUTE_OTHER_ADDRESS (0x802C)

//////////////////////
#define GET_STUN_REQUEST(msg_type)      (msg_type & 0xFEEF)
#define GET_STUN_INDICATION(msg_type)   ((msg_type & 0xFEEF)|0x0010)
#define GET_STUN_SUCCESS_RESP(msg_type)  ((msg_type & 0xFEEF)|0x0100)
#define GET_STUN_ERR_RESP(msg_type)      (msg_type | 0x0110)
/////////// 
#define STUN_HEADER_LENGTH (20)
#define STUN_MAGIC_COOKIE (0x2112A442)

#define IS_STUN_REQUEST(msg_type)       (((msg_type) & 0x0110) == 0x0000)

#define IS_STUN_INDICATION(msg_type)    (((msg_type) & 0x0110) == 0x0010)
#define IS_STUN_SUCCESS_RESP(msg_type)  (((msg_type) & 0x0110) == 0x0100)
#define IS_STUN_ERR_RESP(msg_type)      (((msg_type) & 0x0110) == 0x0110)

////////////// SSODA /////////////////// 
#define STUN_ATTRIBUTE_ADDITIONAL_ADDRESS_FAMILY (0x8032)
#define STUN_ATTRIBUTE_ADDRESS_ERROR_CODE (0x8033)

#define MAX_STUN_MESSAGE_SIZE (65507)
#define STUN_TID_SIZE (12)


#define ns_bcopy(src,dst,sz) bcopy((src),(dst),(sz))
#define nswap16(s) ntohs(s) 
#define nswap32(ul) ntohl(ul)

#define nswap64(ull) ioa_ntoh64(ull)

#define ns_bzero(ptr,sz) bzero((ptr),(sz))

enum SHATYPE {
	SHATYPE_ERROR = -1,
	SHATYPE_DEFAULT = 0,
	SHATYPE_SHA1 = SHATYPE_DEFAULT,
	SHATYPE_SHA256,
	SHATYPE_SHA384,
	SHATYPE_SHA512
};

typedef struct {
	/**
	 * Binary array
	 */
	uint8_t tsx_id[STUN_TID_SIZE];
} stun_tid;

typedef u32bits turn_time_t;
typedef unsigned long band_limit_t;
typedef union {
	struct sockaddr ss;
	struct sockaddr_in s4;
	struct sockaddr_in6 s6;
} ioa_addr;


#if !defined(UNUSED_ARG)
#define UNUSED_ARG(A) do { A=A; } while(0)
#endif

int stun_attr_get_len(stun_attr_ref attr);

buffer_type* stun_attr_get_value(stun_attr_ref attr);

void stun_tid_message_cpy(buffer_type buf, const stun_tid * id);

void stun_tid_generate_in_message_str(buffer_type buf, stun_tid * id);
