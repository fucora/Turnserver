#pragma once
#ifndef STUNPRPTOCAL_H
#define STUNPRPTOCAL_H

#include "SHAmethod.h"
#include "commonTypes.h"
#include "turn.h"

class StunProtocol
{

#pragma region 原始协议
public:
	//uint16_t requestType_Original;//里面包含了请求方法类型(RequestType),返回消息类型(ResponseType)
	//uint16_t requestLength_Original;
	//uint32_t magic_cookie;
	//uint8_t transactionID_Original[12];
	uint16_t* unknown;
	size_t unknown_size;

	uint16_t reuqestHeader_totalLength_nothsVal = 0;
	struct	turn_msg_hdr * reuqestHeader=NULL;

	uint16_t mapped_addr_totalLength_nothsVal = 0;
	struct turn_attr_mapped_address* mapped_addr = NULL; /**< MAPPED-ADDRESS attribute */

	uint16_t xor_mapped_addr_totalLength_nothsVal = 0;
	struct turn_attr_xor_mapped_address* xor_mapped_addr = NULL; /**< XOR-MAPPED-ADDRESS attribute */

	uint16_t alternate_server_totalLength_nothsVal = 0;
	struct turn_attr_alternate_server* alternate_server = NULL; /**< ALTERNATE-SERVER attribute */

	uint16_t nonce_totalLength_nothsVal = 0;
	struct turn_attr_nonce* nonce = NULL; /**< NONCE attribute */

	uint16_t realm_totalLength_nothsVal = 0;
	struct turn_attr_realm* realm = NULL; /**< REALM attribute */

	uint16_t username_totalLength_nothsVal = 0;
	struct turn_attr_username* username = NULL; /**< USERNAME attribute */

	uint16_t error_code_totalLength_nothsVal = 0;
	struct turn_attr_error_code* error_code = NULL; /**< ERROR-CODE attribute */

	uint16_t unknown_attribute_totalLength_nothsVal = 0;
	struct turn_attr_unknown_attribute* unknown_attribute = NULL; /**< UNKNOWN-ATTRIBUTE attribute */

	uint16_t message_integrity_totalLength_nothsVal = 0;
	struct turn_attr_message_integrity* message_integrity = NULL; /**< MESSAGE-INTEGRITY attribute */

	uint16_t fingerprint_totalLength_nothsVal = 0;
	struct turn_attr_fingerprint* fingerprint = NULL; /**< FINGERPRINT attribute */

	uint16_t software_totalLength_nothsVal = 0;
	struct turn_attr_software* software = NULL; /**< SOFTWARE attribute */

	uint16_t channel_number_totalLength_nothsVal = 0;
	struct turn_attr_channel_number* channel_number = NULL; /**< CHANNEL-NUMBER attribute */

	uint16_t lifetime_totalLength_nothsVal = 0;
	struct turn_attr_lifetime* lifetime = NULL; /**< LIFETIME attribute */

	uint16_t peer_addr_totalLength_nothsVal = 0;
	struct turn_attr_xor_peer_address* peer_addr[XOR_PEER_ADDRESS_MAX]; /**< XOR-PEER-ADDRESS attribute */

	uint16_t data_totalLength_nothsVal = 0;
	struct turn_attr_data* data = NULL; /**< DATA attribute */

	uint16_t relayed_addr_totalLength_nothsVal = 0;
	struct turn_attr_xor_relayed_address* relayed_addr = NULL; /**< XOR-RELAYED-ADDRESS attribute */

	uint16_t even_port_totalLength_nothsVal = 0;
	struct turn_attr_even_port* even_port = NULL; /**< REQUESTED-PROPS attribute */

	uint16_t requested_transport_totalLength_nothsVal = 0;
	struct turn_attr_requested_transport* requested_transport = NULL; /**< REQUESTED-TRANSPORT attribute */

	uint16_t dont_fragment_totalLength_nothsVal = 0;
	struct turn_attr_dont_fragment* dont_fragment = NULL; /**< DONT-FRAGMENT attribute */

	uint16_t reservation_token_totalLength_nothsVal = 0;
	struct turn_attr_reservation_token* reservation_token = NULL; /**< RESERVATION-TOKEN attribute */

	uint16_t requested_addr_family_totalLength_nothsVal = 0;
	struct turn_attr_requested_address_family* requested_addr_family = NULL; /**< REQUESTED-ADDRESS-FAMILY attribute (RFC6156) */

	uint16_t connection_id_totalLength_nothsVal = 0;
	struct turn_attr_connection_id* connection_id = NULL; /**< CONNECTION-ID attribute (RFC6062) */
	size_t xor_peer_addr_overflow; /**< If set to 1, not all the XOR-PEER-ADDRESS given in request are in this structure */
#pragma endregion


#pragma region 协议
public:
	bool IsChannelData();
	uint16_t getRequestType();
	uint16_t getRequestLength();
	uint16_t getRequestMethod();
	uint16_t getResponseType();

#pragma endregion

public:
	StunProtocol();
	StunProtocol(char * buf, int datalength);
	bool IsErrorRequest(buffer_type buf);
	void turn_error_response_400(int requestMethod, const uint8_t * transactionID);
	void create_error_response_401(uint16_t requestMethod, const uint8_t * transactionID, char * realmstr, unsigned char * nonce);

	void turn_error_response_420(int requestMethod, const uint8_t * transactionID, const uint16_t * unknown, size_t unknown_size);

	void turn_error_response_403(int requestMethod, const uint8_t * transactionID);

	void turn_error_response_437(int requestMethod, const uint8_t * transactionID);

	void turn_error_response_438(int requestMethod, const uint8_t * transactionID, const char * realm, const uint8_t * nonce);

	void turn_error_response_440(int requestMethod, const uint8_t * transactionID);

	void turn_error_response_441(int requestMethod, const uint8_t * transactionID);

	void turn_error_response_442(int requestMethod, const uint8_t * transactionID);

	void turn_error_response_443(int requestMethod, const uint8_t * transactionID);

	void turn_error_response_446(int requestMethod, const uint8_t * transactionID);

	void turn_error_response_447(int requestMethod, const uint8_t * transactionID);

	void turn_error_response_486(int requestMethod, const uint8_t * transactionID);

	void turn_msg_createpermission_response_create(const uint8_t * id);

	int turn_attr_reservation_token_create(const uint8_t * token);

	void turn_error_response_500(int requestMethod, const uint8_t * transactionID);

	void turn_error_response_508(int requestMethod, const uint8_t * transactionID);

	void turn_attr_xor_mapped_address_create(const socket_base * sock, int transport_protocol, uint32_t cookie, const uint8_t * id);

	void turn_attr_xor_relayed_address_create(const socket_base * sock, int transport_protocol, uint32_t cookie, const uint8_t * id);

	void turn_attr_xor_address_create(uint16_t type, const socket_base * sock, int transport_protocol, uint32_t cookie, const uint8_t * id);

	int turn_msg_channelbind_response_create(const uint8_t * id);

 

	int turn_attr_unknown_attributes_create(const uint16_t * unknown_attributes, size_t attr_size);

	int turn_attr_software_create(const char * software);

	int turn_nonce_is_stale(const char * noncekey);

	int turn_add_message_integrity(const unsigned char * key, size_t key_len, int add_fingerprint);

	int turn_attr_message_integrity_create(const uint8_t * hmac);

	int turn_calculate_integrity_hmac_iov(const unsigned char * key, size_t key_len);

	unsigned char * turn_calculate_integrity_hmac(const unsigned char * buf, unsigned char * userAcountHashkey);

	void turn_msg_refresh_response_create(const uint8_t * transactionID);

	void turn_attr_lifetime_create(uint32_t lifetime);



	int turn_msg_create(uint16_t requestMethod, uint16_t responseType, uint16_t messagelen, const uint8_t * transactionID);
	int turn_attr_connection_id_create(uint32_t id);
	void turn_msg_connectionbind_response_create(const uint8_t * id);
	int turn_msg_allocate_response_create(const uint8_t * id);
	int turn_attr_realm_create(const char * realm);

	int turn_attr_error_create(uint16_t code, const char * reason);
	int turn_attr_nonce_create(const uint8_t * nonce);
	int turn_attr_fingerprint_create(uint32_t fingerprint);
	uint32_t turn_calculate_fingerprint();
	uint8_t * turn_generate_nonce(const char * noncekey);
	int turn_xor_address_cookie(int family, uint8_t * peer_addr, uint16_t * peer_port, const uint8_t * cookie, const uint8_t * msg_id);
	char* getMessageData();
	account_desc* account_desc_new(const char* username, const char* password, const char* realm, account_state state);
	int turn_calculate_authentication_key(const char* username, const char* realm, const char* password, unsigned char* key, size_t key_len);

	~StunProtocol();

private:

	int getAttr(const char * bufferPtr, uint16_t attrtypeHotols);

	void addHeaderMsgLength(uint16_t ntohsVal);

};
#endif
 
