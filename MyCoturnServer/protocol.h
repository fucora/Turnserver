
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
 *创建401错误的信息
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
struct turn_msg_hdr* turn_error_response_401(int method, const uint8_t* id,
	const char* realm, const uint8_t* nonce, size_t nonce_len,
	struct iovec* iov, size_t* index);



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


