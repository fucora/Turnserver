
#include "commonTypes.h"
#include "turn.h"
/**
 * \brief Parse a STUN/TURN message.
 * \param msg raw buffer containing the message
 * \param msg_len size of buffer
 * \param message structures that will contains pointer on message header and
 * attributes.
 * \param unknown array that will be filled with unknown attributes
 * \param unknown_size sizeof initial array, will be filled with the number of
 * unknown options found
 * \return 0 if success, 1 if unknown comprehension-required attributes are
 * found, -1 if problem (malformed packet)
 * \warning If there are more than unknown_size attributes, they will not be put
 * in the array.
 */
int turn_parse_message(const char* msg, ssize_t msg_len,
	struct turn_message* message, uint16_t* unknown, size_t* unknown_size);


/**
 *使用key，进行MD5加密
 * \brief Generate a nonce value.
 *
 * nonce = 64-bit timestamp MD5(timestamp ":" key)
 *
 * When time_t is 4 bytes, the timestamp is padded with 0x30.
 *
 * \param nonce array that will be filled
 * \param len length of nonce
 * \param key key used
 * \param key_len key length
 * \return 0 if success, -1 otherwise
 */
int turn_generate_nonce(uint8_t* nonce, size_t len, uint8_t* key, size_t key_len);
 
/**
 * \brief Create a TURN (or STUN) message.
 * \param type type of the message
 * \param len length of the message without 20 bytes TURN header
 * \param id 96 bit transaction ID
 * \param iov vector
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_msg_create(uint16_t type, uint16_t len,
	const uint8_t* id, struct iovec* iov);

/**
 * \brief Create a ERROR-CODE attribute.
 * \param code error code
 * \param reason reason string
 * \param len reason string length
 * \param iov vector
 * \return pointer on turn_attr_hdr or NULL if problem
 */
struct turn_attr_hdr* turn_attr_error_create(uint16_t code, const char* reason,
	size_t len, struct iovec* iov);
 

/**
 * \brief Create a NONCE attribute.
 * \param nonce seqence of quoted-text or quoted-pair which are defined in RFC 3261 (including quotes)
 * \param len length of nonce
 * \param iov vector
 * \return pointer on turn_attr_hdr or NULL if problem
 */
struct turn_attr_hdr* turn_attr_nonce_create(const uint8_t* nonce, size_t len,struct iovec* iov);


/**
 * \brief Create a SOFTWARE attribute.
 * \param software software description
 * \param len length of software
 * \param iov vector
 * \return pointer on turn_attr_hdr or NULL if problem
 */
struct turn_attr_hdr* turn_attr_software_create(const char* software,size_t len, struct iovec* iov);

/**
 * \brief Compute and add MESSAGE-INTEGRITY and optionnally FINGERPRINT
 * attributes to message.
 * \param iov vector which contains a message and attributes
 * \param index index in the vector, it will be updated to the next unused
 * position if function succeed
 * \param key key used to hash
 * \param key_len length of key
 * \param add_fingerprint if set to 1, this function add FINGERPRINT attribute
 * \return 0 if success, -1 otherwise
 * \note This function set turn_msg_len field of TURN message to big endian (as
 * MESSAGE-INTEGRITY/FINGERPRINT are normally the last attributes added).
 */
int turn_add_message_integrity(struct iovec* iov, size_t* index,const unsigned char* key, size_t key_len, int add_fingerprint);

/**
 * \brief Create a MESSAGE-INTEGRITY attribute.
 * \param hmac the SHA1-HMAC (MUST be 20 bytes length)
 * \param iov vector
 * \return pointer on turn_attr_hdr or NULL if problem
 */
struct turn_attr_hdr* turn_attr_message_integrity_create(const uint8_t* hmac,struct iovec* iov);

/**
 * \brief Calculate the HMAC-SHA1 hash.
 * \param iov vector which contains a message and attributes (without
 * MESSAGE-INTEGRITY)
 * \param iovlen number of element in iov
 * \param key key used to hash
 * \param key_len length of key
 * \param integrity buffer that will received HMAC hash (MUST be at least 20
 * bytes length)
 * \return 0 if success, -1 otherwise
 */
int turn_calculate_integrity_hmac_iov(const struct iovec* iov, size_t iovlen,const unsigned char* key, size_t key_len, unsigned char* integrity);

/**
 * \brief Compute fingerprint and add it to the message.
 * \param iov vector which contains a message and attributes
 * \param index index in the vector, it will be updated to the next unused
 * position if function succeed
 * \return 0 if success, -1 if failure
 */
int turn_add_fingerprint(struct iovec* iov, size_t* index);


/**
 * \brief Create a FINGERPRINT attribute.
 * \param fingerprint fingerprint
 * \param iov vector
 * \return pointer on turn_attr_hdr or NULL if problem
 */
struct turn_attr_hdr* turn_attr_fingerprint_create(uint32_t fingerprint,struct iovec* iov);

/**
 * \brief Calculate the fingerprint using CRC-32 from ITU V.42.
 * \param iov vector which contains a message and attributes (without
 * FINGERPRINT)
 * \param iovlen number of element in iov
 * \return 32 bit fingerprint
 */
uint32_t turn_calculate_fingerprint(const struct iovec* iov, size_t iovlen);

/**
 * \brief Check if nonce is stale.
 * \param nonce nonce
 * \param len length of nonce
 * \param key nonce key
 * \param key_len length of the key
 * \return 1 if nonce is stale, 0 otherwise
 */
int turn_nonce_is_stale(uint8_t* nonce, size_t len, unsigned char* key,size_t key_len);

/* STUN specific error message */
/**
 * \brief Create a complete error 400.
 * \param method method used
 * \param id transaction ID
 * \param iov vector
 * \param index will be filled with the number of element added
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_error_response_400(int method, const uint8_t* id, struct iovec* iov, size_t* index);

/**
 * \brief Create a complete error 401.
 * \param method method used
 * \param id transaction ID
 * \param realm realm value
 * \param nonce nonce value
 * \param nonce_len nonce length
 * \param iov vector
 * \param index will be filled with the number of element added
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_error_response_401(int method, const uint8_t* id, const char* realm, const uint8_t* nonce, size_t nonce_len, struct iovec* iov, size_t* index);

/**
 * \brief Create a complete error 420.
 * \param method method used
 * \param id transaction ID
 * \param unknown array unknown attributes
 * \param unknown_size sizeof unknown array
 * \param iov vector
 * \param index will be filled with the number of element added
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_error_response_420(int method, const uint8_t* id, const uint16_t* unknown, size_t unknown_size, struct iovec* iov,size_t* index);

/**
 * \brief Create a complete error 438.
 * \param method method used
 * \param id transaction ID
 * \param realm realm value
 * \param nonce nonce value
 * \param nonce_len nonce length
 * \param iov vector
 * \param index will be filled with the number of element added
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_error_response_438(int method, const uint8_t* id, const char* realm, const uint8_t* nonce, size_t nonce_len,struct iovec* iov, size_t* index);

/**
 * \brief Create a complete error 500.
 * \param method method used
 * \param id transaction ID
 * \param iov vector
 * \param index will be filled with the number of element added
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_error_response_500(int method, const uint8_t* id,struct iovec* iov, size_t* index);

/* TURN specific error message */

/**
 * \brief Create a complete error 403.
 * \param method method used
 * \param id transaction ID
 * \param iov vector
 * \param index will be filled with the number of element added
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_error_response_403(int method, const uint8_t* id,struct iovec* iov, size_t* index);

/**
 * \brief Create a complete error 437.
 * \param method method used
 * \param id transaction ID
 * \param iov vector
 * \param index will be filled with the number of element added
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_error_response_437(int method, const uint8_t* id,struct iovec* iov, size_t* index);

/**
 * \brief Create a complete error 440.
 * \param method method used
 * \param id transaction ID
 * \param iov vector
 * \param index will be filled with the number of element added
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_error_response_440(int method, const uint8_t* id,struct iovec* iov, size_t* index);

/**
 * \brief Create a complete error 441.
 * \param method method used
 * \param id transaction ID
 * \param iov vector
 * \param index will be filled with the number of element added
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_error_response_441(int method, const uint8_t* id,struct iovec* iov, size_t* index);

/**
 * \brief Create a complete error 442.
 * \param method method used
 * \param id transaction ID
 * \param iov vector
 * \param index will be filled with the number of element added
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_error_response_442(int method, const uint8_t* id,struct iovec* iov, size_t* index);

/**
 * \brief Create a complete error 443.
 * \param method method used
 * \param id transaction ID
 * \param iov vector
 * \param index will be filled with the number of element added
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_error_response_443(int method, const uint8_t* id,struct iovec* iov, size_t* index);

/**
 * \brief Create a complete error 446.
 * \param method method used
 * \param id transaction ID
 * \param iov vector
 * \param index will be filled with the number of element added
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_error_response_446(int method, const uint8_t* id,struct iovec* iov, size_t* index);

/**
 * \brief Create a complete error 447.
 * \param method method used
 * \param id transaction ID
 * \param iov vector
 * \param index will be filled with the number of element added
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_error_response_447(int method, const uint8_t* id,struct iovec* iov, size_t* index);

/**
 * \brief Create a complete error 486.
 * \param method method used
 * \param id transaction ID
 * \param iov vector
 * \param index will be filled with the number of element added
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_error_response_486(int method, const uint8_t* id,struct iovec* iov, size_t* index);

/**
 * \brief Create a complete error 508.
 * \param method method used
 * \param id transaction ID
 * \param iov vector
 * \param index will be filled with the number of element added
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_error_response_508(int method, const uint8_t* id,struct iovec* iov, size_t* index);

/**
 * \brief Create a UNKNOWN-ATTRIBUTE.
 * \param unknown_attributes array of unknown attributes
 * \param attr_size number of element of unknown_attribute array
 * \param iov vector
 */
struct turn_attr_hdr* turn_attr_unknown_attributes_create(const uint16_t* unknown_attributes, size_t attr_size, struct iovec* iov);

/**
 * \brief Create a REALM attribute.
 * \param realm text as described in RFC 3261 (including the quotes)
 * \param len length of realm
 * \param iov vector
 * \return pointer on turn_attr_hdr or NULL if problem
 */
struct turn_attr_hdr* turn_attr_realm_create(const char* realm, size_t len,struct iovec* iov);




