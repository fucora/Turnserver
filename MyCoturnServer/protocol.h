
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
