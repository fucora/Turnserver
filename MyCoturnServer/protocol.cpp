
#include "protocol.h"

int turn_parse_message(const char* msg, ssize_t msg_len,
	struct turn_message* message, uint16_t* unknown, size_t* unknown_size)
{
	struct turn_msg_hdr* hdr = NULL;
	/* attributes length */
	ssize_t len = 0;
	const char* ptr = msg;
	size_t unknown_idx = 0;
	/* count of XOR-PEER-ADDRESS attribute */
	size_t xor_peer_address_nb = 0;

	/* zeroed structure */
	memset(message, 0x00, sizeof(struct turn_message));

	/* STUN/TURN header MUST be 20 bytes length */
	if (msg_len < 20)
	{
		/* not a STUN/TURN message */
		return -1;
	}

	hdr = (struct turn_msg_hdr*)ptr;
	message->msg = hdr; /* keep pointer */
	len = ntohs(hdr->turn_msg_len);

	/* check if the length coherent with packet length received */
	if ((len + 20) > msg_len)
	{
		/* too short */
		return -1;
	}

	ptr += 20; /* advance to first attribute */

	if (len % 4)
	{
		/* length is a multipe of four */
		return -1;
	}

	while (len >= 4)
	{
		struct turn_attr_hdr* attr = (struct turn_attr_hdr*)ptr;

		/* FINGERPRINT MUST be the last attributes if present */
		if (message->fingerprint)
		{
			/* when present, the FINGERPRINT attribute MUST be the last attribute */
			/* ignore other message
			 */
			return 0;
		}

		/* MESSAGE-INTEGRITY is the last attribute except if FINGERPRINT follow
		 * it
		 */
		if (message->message_integrity && ntohs(attr->turn_attr_type) !=
			STUN_ATTR_FINGERPRINT)
		{
			/* with the exception of the FINGERPRINT attribute [...]
			 * agents MUST ignore all other attributes that follow MESSAGE-INTEGRITY
			 */
			return 0;
		}

		switch (ntohs(attr->turn_attr_type))
		{
		case STUN_ATTR_MAPPED_ADDRESS:
			message->mapped_addr = (struct turn_attr_mapped_address*)ptr;
			break;
		case STUN_ATTR_XOR_MAPPED_ADDRESS:
			message->xor_mapped_addr = (struct turn_attr_xor_mapped_address*)ptr;
			break;
		case STUN_ATTR_ALTERNATE_SERVER:
			message->alternate_server = (struct turn_attr_alternate_server*)ptr;
			break;
		case STUN_ATTR_NONCE:
			message->nonce = (struct turn_attr_nonce*)ptr;
			break;
		case STUN_ATTR_REALM:
			message->realm = (struct turn_attr_realm*)ptr;
			break;
		case STUN_ATTR_USERNAME:
			message->username = (struct turn_attr_username*)ptr;
			break;
		case STUN_ATTR_ERROR_CODE:
			message->error_code = (struct turn_attr_error_code*)ptr;
			break;
		case STUN_ATTR_UNKNOWN_ATTRIBUTES:
			message->unknown_attribute = (struct turn_attr_unknown_attribute*)ptr;
			break;
		case STUN_ATTR_MESSAGE_INTEGRITY:
			message->message_integrity = (struct turn_attr_message_integrity*)ptr;
			break;
		case STUN_ATTR_FINGERPRINT:
			message->fingerprint = (struct turn_attr_fingerprint*)ptr;
			break;
		case STUN_ATTR_SOFTWARE:
			message->software = (struct turn_attr_software*)ptr;
			break;
		case TURN_ATTR_CHANNEL_NUMBER:
			message->channel_number = (struct turn_attr_channel_number*)ptr;
			break;
		case TURN_ATTR_LIFETIME:
			message->lifetime = (struct turn_attr_lifetime*)ptr;
			break;
		case TURN_ATTR_XOR_PEER_ADDRESS:
			if (xor_peer_address_nb < XOR_PEER_ADDRESS_MAX)
			{
				message->peer_addr[xor_peer_address_nb] =
					(struct turn_attr_xor_peer_address*)ptr;
				xor_peer_address_nb++;
			}
			else
			{
				/* too many XOR-PEER-ADDRESS attribute,
				 * this will inform process_createpermission() to reject the
				 * request with a 508 error
				 */
				message->xor_peer_addr_overflow = 1;
			}
			break;
		case TURN_ATTR_DATA:
			message->data = (struct turn_attr_data*)ptr;
			break;
		case TURN_ATTR_XOR_RELAYED_ADDRESS:
			message->relayed_addr = (struct turn_attr_xor_relayed_address*)ptr;
			break;
		case TURN_ATTR_EVEN_PORT:
			message->even_port = (struct turn_attr_even_port*)ptr;
			break;
		case TURN_ATTR_REQUESTED_TRANSPORT:
			message->requested_transport =
				(struct turn_attr_requested_transport*)ptr;
			break;
		case TURN_ATTR_DONT_FRAGMENT:
			message->dont_fragment = (struct turn_attr_dont_fragment*)ptr;
			break;
		case TURN_ATTR_RESERVATION_TOKEN:
			message->reservation_token = (struct turn_attr_reservation_token*)ptr;
			break;
		case TURN_ATTR_REQUESTED_ADDRESS_FAMILY:
			message->requested_addr_family =
				(struct turn_attr_requested_address_family*)ptr;
			break;
		case TURN_ATTR_CONNECTION_ID:
			message->connection_id = (struct turn_attr_connection_id*)ptr;
			break;
		default:
			if (ntohs(attr->turn_attr_type) <= 0x7fff)
			{
				/* comprehension-required attribute but server does not understand
				 * it
				 */
				if (!(*unknown_size))
				{
					break;
				}
				unknown[unknown_idx] = htons(attr->turn_attr_type);
				(*unknown_size)--;
				unknown_idx++;
			}
			break;
		}

		/* advance the TLV header (4 bytes) and contents (attr_len) + padding */
		len -= (4 + ntohs(attr->turn_attr_len));
		ptr += (4 + ntohs(attr->turn_attr_len));

		{
			size_t m = (4 + ntohs(attr->turn_attr_len)) % 4;

			if (m)
			{
				len -= (4 - m);
				ptr += (4 - m);
			}
		}
	}

	*unknown_size = unknown_idx;

	return 0;
}


int turn_generate_nonce(uint8_t* nonce, size_t len, uint8_t* key, size_t key_len)
{
	time_t t;
	char c = ':';
	MD5_CTX ctx;
	unsigned char md_buf[MD5_DIGEST_LENGTH];

	if (len < (16 + MD5_DIGEST_LENGTH))
	{
		return -1;
	}

	MD5_Init(&ctx);

	/* timestamp */
	t = time(NULL);

	/* add expire period */
	t += TURN_DEFAULT_NONCE_LIFETIME;

	t = (time_t)htonl((uint32_t)t);
	hex_convert((unsigned char*)&t, sizeof(time_t), nonce, sizeof(time_t) * 2);

	if (sizeof(time_t) == 4) /* 32 bit */
	{
		memset(nonce + 8, 0x30, 8);
	}

	MD5_Update(&ctx, nonce, 16); /* time */
	MD5_Update(&ctx, &c, 1);
	MD5_Update(&ctx, key, key_len);
	MD5_Final(md_buf, &ctx);

	/* add MD5 at the end of the nonce */
	hex_convert(md_buf, MD5_DIGEST_LENGTH, nonce + 16, len - 16);

	return 0;
}

 
struct turn_msg_hdr* turn_msg_create(uint16_t type, uint16_t len,const uint8_t* id, struct iovec* iov)
{
	struct turn_msg_hdr* ret = NULL;

	if ((ret = (turn_msg_hdr*)malloc(sizeof(struct turn_msg_hdr))) == NULL)
	{
		return NULL;
	}

	ret->turn_msg_type = htons(type);
	ret->turn_msg_len = htons(len);
	ret->turn_msg_cookie = htonl(STUN_MAGIC_COOKIE);
	memcpy(ret->turn_msg_id, id, 12);

	iov->iov_base = ret;
	iov->iov_len = sizeof(struct turn_msg_hdr);

	return ret;
}

struct turn_attr_hdr* turn_attr_error_create(uint16_t code, const char* reason,
	size_t len, struct iovec* iov)
{
	struct turn_attr_error_code* ret = NULL;
	uint8_t _class = code / 100;
	uint8_t number = code % 100;
	size_t real_len = len;

	/* reason can be as long as 763 bytes */
	if (len > 763)
	{
		return NULL;
	}

	/* class MUST be between 3 and 6 */
	if (_class < 3 || _class > 6)
	{
		return NULL;
	}

	/* number MUST be between 0 and 99 */
	if (number > 99)
	{
		return NULL;
	}

	/* real_len, attribute header size and padding must be a multiple of four */
	if ((real_len + 4) % 4)
	{
		real_len += (4 - (real_len % 4));
	}

	if (!(ret = (turn_attr_error_code*)malloc(sizeof(struct turn_attr_error_code) + real_len)))
	{
		return NULL;
	}

	ret->turn_attr_type = htons(STUN_ATTR_ERROR_CODE);
	ret->turn_attr_len = htons(4 + real_len);

	if (is_little_endian())
	{
		ret->turn_attr_reserved_class = _class << 16;
	}
	else /* big endian */
	{
		ret->turn_attr_reserved_class = _class;
	}

	ret->turn_attr_number = number;

	/* even if strlen(reason) < len, strncpy will add extra-zero
	 * also no need to add final NULL character since length is known (TLV)
	 */
	strncpy((char*)ret->turn_attr_reason, reason, real_len);

	iov->iov_base = ret;
	iov->iov_len = sizeof(struct turn_attr_error_code) + real_len;

	return (struct turn_attr_hdr*)ret;
}


struct turn_attr_hdr* turn_attr_realm_create(const char* realm, size_t len,
	struct iovec* iov)
{
	struct turn_attr_realm* ret = NULL;
	size_t real_len = len;

	/* realm can be as long as 763 bytes */
	if (len > 763)
	{
		return NULL;
	}

	/* real_len, attribute header size and padding must be a multiple of four */
	if ((real_len + 4) % 4)
	{
		real_len += (4 - (real_len % 4));
	}

	if (!(ret = (turn_attr_realm*)malloc(sizeof(struct turn_attr_realm) + real_len)))
	{
		return NULL;
	}

	ret->turn_attr_type = htons(STUN_ATTR_REALM);
	ret->turn_attr_len = htons(len);
	memset(ret->turn_attr_realm, 0x00, real_len);
	memcpy(ret->turn_attr_realm, realm, len);

	iov->iov_base = ret;
	iov->iov_len = sizeof(struct turn_attr_realm) + real_len;

	return (struct turn_attr_hdr*)ret;
}


struct turn_attr_hdr* turn_attr_nonce_create(const uint8_t* nonce, size_t len, struct iovec* iov)
{
	struct turn_attr_nonce* ret = NULL;
	size_t real_len = len;

	/* nonce can be as long as 763 bytes */
	if (len > 763)
	{
		return NULL;
	}

	/* real_len, attribute header size and padding must be a multiple of four */
	if ((real_len + 4) % 4)
	{
		real_len += (4 - (real_len % 4));
	}

	if (!(ret = (turn_attr_nonce*)malloc(sizeof(struct turn_attr_nonce) + real_len)))
	{
		return NULL;
	}

	ret->turn_attr_type = htons(STUN_ATTR_NONCE);
	ret->turn_attr_len = htons(len);
	memset(ret->turn_attr_nonce, 0x00, real_len);
	memcpy(ret->turn_attr_nonce, nonce, len);

	iov->iov_base = ret;
	iov->iov_len = sizeof(struct turn_attr_nonce) + real_len;

	return (struct turn_attr_hdr*)ret;
}

struct turn_attr_hdr* turn_attr_software_create(const char* software, size_t len, struct iovec* iov)
{
	struct turn_attr_software* ret = NULL;
	size_t real_len = len;

	/* reason can be as long as 763 bytes */
	if (len > 763)
	{
		return NULL;
	}

	/* real_len, attribute header size and padding must be a multiple of four */
	if ((real_len + 4) % 4)
	{
		real_len += (4 - (real_len % 4));
	}

	if (!(ret = (turn_attr_software*)malloc(sizeof(struct turn_attr_software) + real_len)))
	{
		return NULL;
	}

	ret->turn_attr_type = htons(STUN_ATTR_SOFTWARE);
	ret->turn_attr_len = htons(len);
	memset(ret->turn_attr_software, 0x00, real_len);
	memcpy(ret->turn_attr_software, software, len);

	iov->iov_base = ret;
	iov->iov_len = sizeof(struct turn_attr_software) + real_len;

	return (struct turn_attr_hdr*)ret;
}


int turn_add_message_integrity(struct iovec* iov, size_t* idx, const unsigned char* key, size_t key_len, int add_fingerprint)
{
	struct turn_attr_hdr* attr = NULL;
	struct turn_msg_hdr* hdr = (turn_msg_hdr*)iov[0].iov_base;

	if (*idx == 0)
	{
		/* could not place message-integrity or fingerprint in first place */
		return -1;
	}

	if (!(attr = turn_attr_message_integrity_create(NULL, &iov[*idx])))
	{
		return -1;
	}
	hdr->turn_msg_len += iov[(*idx)].iov_len;
	(*idx)++;

	/* compute HMAC */
	/* convert length to big endian */
	hdr->turn_msg_len = htons(hdr->turn_msg_len);

	/* do not take into account the attribute itself */
	turn_calculate_integrity_hmac_iov(iov, (*idx) - 1, key, key_len,((struct turn_attr_message_integrity*)attr)->turn_attr_hmac);

	hdr->turn_msg_len = ntohs(hdr->turn_msg_len);

	if (add_fingerprint)
	{
		turn_add_fingerprint(iov, idx);
	}

	hdr->turn_msg_len = htons(hdr->turn_msg_len);

	return 0;
}


int turn_calculate_integrity_hmac_iov(const struct iovec* iov, size_t iovlen,const unsigned char* key, size_t key_len, unsigned char* integrity)
{
	HMAC_CTX ctx;
	unsigned int md_len = SHA_DIGEST_LENGTH;
	size_t i = 0;

	/* MESSAGE-INTEGRITY uses HMAC-SHA1 */
	HMAC_CTX_init(&ctx);
	HMAC_Init(&ctx, key, key_len, EVP_sha1());

	for (i = 0; i < iovlen; i++)
	{
		HMAC_Update(&ctx, (const unsigned char *)iov[i].iov_base, iov[i].iov_len);
	}
	HMAC_Final(&ctx, integrity, &md_len); /* HMAC-SHA1 is 20 bytes length */

	HMAC_CTX_cleanup(&ctx);

	return 0;
}

struct turn_attr_hdr* turn_attr_message_integrity_create(const uint8_t* hmac, struct iovec* iov)
{
	struct turn_attr_message_integrity* ret = NULL;

	if (!(ret = (turn_attr_message_integrity*)malloc(sizeof(struct turn_attr_message_integrity))))
	{
		return NULL;
	}

	ret->turn_attr_type = htons(STUN_ATTR_MESSAGE_INTEGRITY);
	ret->turn_attr_len = htons(20);

	if (hmac)
	{
		memcpy(ret->turn_attr_hmac, hmac, 20);
	}
	else
	{
		memset(ret->turn_attr_hmac, 0x00, 20);
	}

	iov->iov_base = ret;
	iov->iov_len = sizeof(struct turn_attr_message_integrity);

	return (struct turn_attr_hdr*)ret;
}



int turn_add_fingerprint(struct iovec* iov, size_t* idx)
{
	struct turn_attr_hdr* attr = NULL;
	struct turn_msg_hdr* hdr = (turn_msg_hdr*)iov[0].iov_base;

	if (*idx == 0)
	{
		/* could not place fingerprint in first place */
		return -1;
	}

	/* add a fingerprint */
	if (!(attr = turn_attr_fingerprint_create(0, &iov[(*idx)])))
	{
		return -1;
	}
	hdr->turn_msg_len += iov[(*idx)].iov_len;
	(*idx)++;

	/* compute fingerprint */
	/* convert to big endian */
	hdr->turn_msg_len = htons(hdr->turn_msg_len);

	/* do not take into account the attribute itself */
	((struct turn_attr_fingerprint*)attr)->turn_attr_crc = htonl(turn_calculate_fingerprint(iov, (*idx) - 1));
	((struct turn_attr_fingerprint*)attr)->turn_attr_crc ^= htonl(STUN_FINGERPRINT_XOR_VALUE);

	hdr->turn_msg_len = ntohs(hdr->turn_msg_len);

	return 0;
}

uint32_t turn_calculate_fingerprint(const struct iovec* iov, size_t iovlen)
{
	uint32_t crc = 0;
	size_t i = 0;

	for (i = 0; i < iovlen; i++)
	{
		crc = crc32_generate((uint8_t*)iov[i].iov_base, iov[i].iov_len, crc);
	}

	return crc;
}


struct turn_attr_hdr* turn_attr_fingerprint_create(uint32_t fingerprint,struct iovec* iov)
{
	struct turn_attr_fingerprint* ret = NULL;

	if (!(ret = (turn_attr_fingerprint*)malloc(sizeof(struct turn_attr_fingerprint))))
	{
		return NULL;
	}

	ret->turn_attr_type = htons(STUN_ATTR_FINGERPRINT);
	ret->turn_attr_len = htons(4);
	ret->turn_attr_crc = htonl(fingerprint);

	iov->iov_base = ret;
	iov->iov_len = sizeof(struct turn_attr_fingerprint);

	return (struct turn_attr_hdr*)ret;
}

struct turn_msg_hdr* turn_error_response_400(int method, const uint8_t* id, struct iovec* iov, size_t* idx)
{
	struct turn_msg_hdr* error = NULL;
	struct turn_attr_hdr* attr = NULL;

	/* header */
	if (!(error = turn_msg_create(method | STUN_ERROR_RESP, 0, id, &iov[*idx])))
	{
		return NULL;
	}
	(*idx)++;

	/* error-code */
	if (!(attr = turn_attr_error_create(400, STUN_ERROR_400, sizeof(STUN_ERROR_400), &iov[*idx])))
	{
		iovec_free_data(iov, *idx);
		return NULL;
	}
	error->turn_msg_len += iov[*idx].iov_len;
	(*idx)++;

	return error;
}


struct turn_msg_hdr* turn_error_response_401(int method, const uint8_t* id,
	const char* realm, const uint8_t* nonce, size_t nonce_len,
	struct iovec* iov, size_t* idx)
{
	struct turn_msg_hdr* error = NULL;
	struct turn_attr_hdr* attr = NULL;

	/* header */
	if (!(error = turn_msg_create(method | STUN_ERROR_RESP, 0, id, &iov[*idx])))
	{
		return NULL;
	}
	(*idx)++;

	/* error-code */
	if (!(attr = turn_attr_error_create(401, STUN_ERROR_401,
		sizeof(STUN_ERROR_401), &iov[*idx])))
	{
		iovec_free_data(iov, *idx);
		return NULL;
	}
	error->turn_msg_len += iov[*idx].iov_len;
	(*idx)++;

	/* realm */
	if (!(attr = turn_attr_realm_create(realm, strlen(realm), &iov[*idx])))
	{
		iovec_free_data(iov, *idx);
		return NULL;
	}
	error->turn_msg_len += iov[*idx].iov_len;
	(*idx)++;

	/* nonce */
	if (!(attr = turn_attr_nonce_create(nonce, nonce_len, &iov[*idx])))
	{
		iovec_free_data(iov, *idx);
		return NULL;
	}
	error->turn_msg_len += iov[*idx].iov_len;
	(*idx)++;

	return error;
}

struct turn_msg_hdr* turn_error_response_420(int method, const uint8_t* id,
	const uint16_t* unknown, size_t unknown_size, struct iovec* iov,
	size_t* idx)
{
	struct turn_msg_hdr* error = NULL;
	struct turn_attr_hdr* attr = NULL;

	/* header */
	if (!(error = turn_msg_create(method | STUN_ERROR_RESP, 0, id, &iov[*idx])))
	{
		return NULL;
	}
	(*idx)++;

	/* error-code */
	if (!(attr = turn_attr_error_create(420, STUN_ERROR_420,
		sizeof(STUN_ERROR_420), &iov[*idx])))
	{
		iovec_free_data(iov, *idx);
		return NULL;
	}
	error->turn_msg_len += iov[*idx].iov_len;
	(*idx)++;

	if (!(attr = turn_attr_unknown_attributes_create(unknown, unknown_size,
		&iov[*idx])))
	{
		return NULL;
	}
	error->turn_msg_len += iov[*idx].iov_len;
	(*idx)++;

	return error;
}

struct turn_msg_hdr* turn_error_response_438(int method, const uint8_t* id,
	const char* realm, const uint8_t* nonce, size_t nonce_len,
	struct iovec* iov, size_t* idx)
{
	struct turn_msg_hdr* error = NULL;
	struct turn_attr_hdr* attr = NULL;

	/* header */
	if (!(error = turn_msg_create(method | STUN_ERROR_RESP, 0, id, &iov[*idx])))
	{
		return NULL;
	}
	(*idx)++;

	/* error-code */
	if (!(attr = turn_attr_error_create(438, STUN_ERROR_438,
		sizeof(STUN_ERROR_438), &iov[*idx])))
	{
		iovec_free_data(iov, *idx);
		return NULL;
	}
	error->turn_msg_len += iov[*idx].iov_len;
	(*idx)++;

	/* realm */
	if (!(attr = turn_attr_realm_create(realm, strlen(realm), &iov[*idx])))
	{
		iovec_free_data(iov, *idx);
		return NULL;
	}
	error->turn_msg_len += iov[*idx].iov_len;
	(*idx)++;

	/* nonce */
	if (!(attr = turn_attr_nonce_create(nonce, nonce_len, &iov[*idx])))
	{
		iovec_free_data(iov, *idx);
		return NULL;
	}
	error->turn_msg_len += iov[*idx].iov_len;
	(*idx)++;

	return error;
}

struct turn_msg_hdr* turn_error_response_500(int method, const uint8_t* id,
	struct iovec* iov, size_t* idx)
{
	struct turn_msg_hdr* error = NULL;
	struct turn_attr_hdr* attr = NULL;

	/* header */
	if (!(error = turn_msg_create(method | STUN_ERROR_RESP, 0, id, &iov[*idx])))
	{
		return NULL;
	}
	(*idx)++;

	/* error-code */
	if (!(attr = turn_attr_error_create(500, STUN_ERROR_500,
		sizeof(STUN_ERROR_500), &iov[*idx])))
	{
		iovec_free_data(iov, *idx);
		return NULL;
	}
	error->turn_msg_len += iov[*idx].iov_len;
	(*idx)++;

	return error;
}

struct turn_msg_hdr* turn_error_response_403(int method, const uint8_t* id,
	struct iovec* iov, size_t* idx)
{
	struct turn_msg_hdr* error = NULL;
	struct turn_attr_hdr* attr = NULL;

	/* header */
	if (!(error = turn_msg_create(method | STUN_ERROR_RESP, 0, id, &iov[*idx])))
	{
		return NULL;
	}
	(*idx)++;

	/* error-code */
	if (!(attr = turn_attr_error_create(403, TURN_ERROR_403,
		sizeof(TURN_ERROR_403), &iov[*idx])))
	{
		iovec_free_data(iov, *idx);
		return NULL;
	}
	error->turn_msg_len += iov[*idx].iov_len;
	(*idx)++;

	return error;
}

struct turn_msg_hdr* turn_error_response_437(int method, const uint8_t* id,
	struct iovec* iov, size_t* idx)
{
	struct turn_msg_hdr* error = NULL;
	struct turn_attr_hdr* attr = NULL;

	/* header */
	if (!(error = turn_msg_create(method | STUN_ERROR_RESP, 0, id, &iov[*idx])))
	{
		return NULL;
	}
	(*idx)++;

	/* error-code */
	if (!(attr = turn_attr_error_create(437, TURN_ERROR_437,
		sizeof(TURN_ERROR_437), &iov[*idx])))
	{
		iovec_free_data(iov, *idx);
		return NULL;
	}
	error->turn_msg_len += iov[*idx].iov_len;
	(*idx)++;

	return error;
}

struct turn_msg_hdr* turn_error_response_440(int method, const uint8_t* id,
	struct iovec* iov, size_t* idx)
{
	struct turn_msg_hdr* error = NULL;
	struct turn_attr_hdr* attr = NULL;

	/* header */
	if (!(error = turn_msg_create(method | STUN_ERROR_RESP, 0, id, &iov[*idx])))
	{
		return NULL;
	}
	(*idx)++;

	/* error-code */
	if (!(attr = turn_attr_error_create(440, TURN_ERROR_440,
		sizeof(TURN_ERROR_440), &iov[*idx])))
	{
		iovec_free_data(iov, *idx);
		return NULL;
	}
	error->turn_msg_len += iov[*idx].iov_len;
	(*idx)++;

	return error;
}

struct turn_msg_hdr* turn_error_response_441(int method, const uint8_t* id,
	struct iovec* iov, size_t* idx)
{
	struct turn_msg_hdr* error = NULL;
	struct turn_attr_hdr* attr = NULL;

	/* header */
	if (!(error = turn_msg_create(method | STUN_ERROR_RESP, 0, id, &iov[*idx])))
	{
		return NULL;
	}
	(*idx)++;

	/* error-code */
	if (!(attr = turn_attr_error_create(441, TURN_ERROR_441,
		sizeof(TURN_ERROR_441), &iov[*idx])))
	{
		iovec_free_data(iov, *idx);
		return NULL;
	}
	error->turn_msg_len += iov[*idx].iov_len;
	(*idx)++;

	return error;
}

struct turn_msg_hdr* turn_error_response_442(int method, const uint8_t* id,
	struct iovec* iov, size_t* idx)
{
	struct turn_msg_hdr* error = NULL;
	struct turn_attr_hdr* attr = NULL;

	/* header */
	if (!(error = turn_msg_create(method | STUN_ERROR_RESP, 0, id, &iov[*idx])))
	{
		return NULL;
	}
	(*idx)++;

	/* error-code */
	if (!(attr = turn_attr_error_create(442, TURN_ERROR_442,
		sizeof(TURN_ERROR_442), &iov[*idx])))
	{
		iovec_free_data(iov, *idx);
		return NULL;
	}
	error->turn_msg_len += iov[*idx].iov_len;
	(*idx)++;

	return error;
}

struct turn_msg_hdr* turn_error_response_443(int method, const uint8_t* id,
	struct iovec* iov, size_t* idx)
{
	struct turn_msg_hdr* error = NULL;
	struct turn_attr_hdr* attr = NULL;

	/* header */
	if (!(error = turn_msg_create(method | STUN_ERROR_RESP, 0, id, &iov[*idx])))
	{
		return NULL;
	}
	(*idx)++;

	/* error-code */
	if (!(attr = turn_attr_error_create(443, TURN_ERROR_443,
		sizeof(TURN_ERROR_443), &iov[*idx])))
	{
		iovec_free_data(iov, *idx);
		return NULL;
	}
	error->turn_msg_len += iov[*idx].iov_len;
	(*idx)++;

	return error;
}

struct turn_msg_hdr* turn_error_response_446(int method, const uint8_t* id,
	struct iovec* iov, size_t* idx)
{
	struct turn_msg_hdr* error = NULL;
	struct turn_attr_hdr* attr = NULL;

	/* header */
	if (!(error = turn_msg_create(method | STUN_ERROR_RESP, 0, id, &iov[*idx])))
	{
		return NULL;
	}
	(*idx)++;

	/* error-code */
	if (!(attr = turn_attr_error_create(446, TURN_ERROR_446,
		sizeof(TURN_ERROR_446), &iov[*idx])))
	{
		iovec_free_data(iov, *idx);
		return NULL;
	}
	error->turn_msg_len += iov[*idx].iov_len;
	(*idx)++;

	return error;
}

struct turn_msg_hdr* turn_error_response_447(int method, const uint8_t* id,
	struct iovec* iov, size_t* idx)
{
	struct turn_msg_hdr* error = NULL;
	struct turn_attr_hdr* attr = NULL;

	/* header */
	if (!(error = turn_msg_create(method | STUN_ERROR_RESP, 0, id, &iov[*idx])))
	{
		return NULL;
	}
	(*idx)++;

	/* error-code */
	if (!(attr = turn_attr_error_create(447, TURN_ERROR_447,
		sizeof(TURN_ERROR_447), &iov[*idx])))
	{
		iovec_free_data(iov, *idx);
		return NULL;
	}
	error->turn_msg_len += iov[*idx].iov_len;
	(*idx)++;

	return error;
}

struct turn_msg_hdr* turn_error_response_486(int method, const uint8_t* id,struct iovec* iov, size_t* idx)
{
	struct turn_msg_hdr* error = NULL;
	struct turn_attr_hdr* attr = NULL;

	/* header */
	if (!(error = turn_msg_create(method | STUN_ERROR_RESP, 0, id, &iov[*idx])))
	{
		return NULL;
	}
	(*idx)++;

	/* error-code */
	if (!(attr = turn_attr_error_create(486, TURN_ERROR_486,
		sizeof(TURN_ERROR_486), &iov[*idx])))
	{
		iovec_free_data(iov, *idx);
		return NULL;
	}
	error->turn_msg_len += iov[*idx].iov_len;
	(*idx)++;

	return error;
}

struct turn_msg_hdr* turn_error_response_508(int method, const uint8_t* id,struct iovec* iov, size_t* idx)
{
	struct turn_msg_hdr* error = NULL;
	struct turn_attr_hdr* attr = NULL;

	/* header */
	if (!(error = turn_msg_create(method | STUN_ERROR_RESP, 0, id, &iov[*idx])))
	{
		return NULL;
	}
	(*idx)++;

	/* error-code */
	if (!(attr = turn_attr_error_create(508, TURN_ERROR_508,
		sizeof(TURN_ERROR_508), &iov[*idx])))
	{
		iovec_free_data(iov, *idx);
		return NULL;
	}
	error->turn_msg_len += iov[*idx].iov_len;
	(*idx)++;

	return error;
}
 
struct turn_attr_hdr* turn_attr_unknown_attributes_create(const uint16_t* unknown_attributes, size_t attr_size, struct iovec* iov)
{
	size_t len = 0;
	size_t tmp_len = 0;
	struct turn_attr_unknown_attribute* ret = NULL;
	uint16_t* ptr = NULL;
	size_t i = 0;

	/* length of the attributes MUST be a multiple of 4 bytes
	 * so it must be a pair number of attributes
	 */
	len = attr_size + (attr_size % 2);

	/* each attribute has 2 bytes length */
	if (!(ret = (turn_attr_unknown_attribute*)malloc(sizeof(struct turn_attr_unknown_attribute) + (len * 2))))
	{
		return NULL;
	}

	ret->turn_attr_type = htons(STUN_ATTR_UNKNOWN_ATTRIBUTES);
	ret->turn_attr_len = htons(attr_size);

	ptr = (uint16_t*)ret->turn_attr_attributes;
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

	iov->iov_base = ret;
	iov->iov_len = sizeof(struct turn_attr_unknown_attribute) + (len * 2);
	return (struct turn_attr_hdr*)ret;
}


int turn_nonce_is_stale(uint8_t* nonce, size_t len, unsigned char* key,size_t key_len)
{
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
	MD5_Update(&ctx, key, key_len);
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
