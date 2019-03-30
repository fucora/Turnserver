#pragma once
#include "commonTypes.h"
#include "turn.h"

class StunProtocol
{

#pragma region ԭʼЭ��
public:
	//uint16_t requestType_Original;//������������󷽷�����(RequestType),������Ϣ����(ResponseType)
	//uint16_t requestLength_Original;
	//uint32_t magic_cookie;
	//uint8_t transactionID_Original[12];
	turn_msg_hdr * reuqestHeader;

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


#pragma region Э��
public:
	   bool IsChannelData();
	   uint16_t getRequestType();
	   uint16_t getRequestLength();
	   uint16_t getRequestMethod();
	   uint16_t getResponseType();

	   bool IsErrorRequest();

	   unsigned char * get_generate_nonce(char * key, size_t key_len);


#pragma endregion

public:
	StunProtocol();
	StunProtocol(buffer_type data, int length);  
	void create_error_response_401(uint16_t requestMethod, const uint8_t * transactionID, char * realmstr, unsigned char * nonce);

	int turn_attr_software_create(const char * software);

	void turn_msg_create(uint16_t requestMethod, uint16_t responseType, uint16_t messagelen, const uint8_t * transactionID);
	int turn_attr_realm_create(const char * realm);

	int turn_attr_error_create(uint16_t code, const char * reason);
	int turn_attr_nonce_create(const uint8_t * nonce);
	int turn_attr_fingerprint_create(uint32_t fingerprint);
	uint32_t turn_calculate_fingerprint();
	~StunProtocol();

private:
	int getAttr(const char * bufferPtr, uint16_t attrtype);

};

turn_attr_hdr * turn_attr_realm_create(const char * realm);
