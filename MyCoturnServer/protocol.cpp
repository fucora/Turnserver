
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


struct turn_msg_hdr* turn_error_response_401(int method, const uint8_t* id, const char* realm, const uint8_t* nonce, size_t nonce_len, struct iovec* iov, size_t* idx)
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
	if (!(attr = turn_attr_error_create(401, STUN_ERROR_401, sizeof(STUN_ERROR_401), &iov[*idx])))
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


struct turn_msg_hdr* turn_msg_create(uint16_t type, uint16_t len,
	const uint8_t* id, struct iovec* iov)
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