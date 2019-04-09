#include "SHAmethod.h"

//¼ÓÃÜÀàÐÍ
enum _SHATYPE {
	SHATYPE_ERROR = -1,
	SHATYPE_DEFAULT = 0,
	SHATYPE_SHA1 = SHATYPE_DEFAULT,
	SHATYPE_SHA256,
	SHATYPE_SHA384,
	SHATYPE_SHA512
};

typedef enum {
	TURN_CREDENTIALS_NONE = 0,
	TURN_CREDENTIALS_LONG_TERM,
	TURN_CREDENTIALS_SHORT_TERM,
	TURN_CREDENTIALS_UNDEFINED
} turn_credential_type;


int ct = TURN_CREDENTIALS_SHORT_TERM;
int shatype = SHATYPE_SHA1;


SHAmethod::SHAmethod(turn_attr_message_integrity* message_integrity)
{
	auto SHAsize = ntohs(message_integrity->turn_attr_len);
	switch (SHAsize) {
	case 32:
		shatype = SHATYPE_SHA256;
		break;
	case 48:
		shatype = SHATYPE_SHA384;
		break;
	case 64:
		shatype = SHATYPE_SHA512;
		break;
	case 20:
		shatype = SHATYPE_SHA1;
		break;
	default:
		shatype = SHATYPE_SHA1;
	};
}


unsigned char * stun_calculate_password_hmac(const unsigned char *buf, size_t len, const unsigned char *password, unsigned int *hmac_len)
{
	unsigned char *hmac;


	size_t pwdlen = strlen((const char*)password);

	if (shatype == SHATYPE_SHA256) {
		if (!HMAC(EVP_sha256(), password, pwdlen, buf, len, hmac, hmac_len)) {
			return NULL;
		}
	}
	else if (shatype == SHATYPE_SHA384) {
		if (!HMAC(EVP_sha384(), password, pwdlen, buf, len, hmac, hmac_len)) {
			return NULL;
		}
	}
	else if (shatype == SHATYPE_SHA512) {
		if (!HMAC(EVP_sha512(), password, pwdlen, buf, len, hmac, hmac_len)) {
			return NULL;
		}
	}
	else {
		if (!HMAC(EVP_sha1(), password, pwdlen, buf, len, hmac, hmac_len)) {
			return NULL;
		}
	}


	return hmac;
}



SHAmethod::~SHAmethod()
{
}
