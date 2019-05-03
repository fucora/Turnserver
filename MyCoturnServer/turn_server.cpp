
#include "turn_server.h"


unsigned long bandwidth = 1024;//带宽

char* listen_address = "127.0.0.1";
char* nonce_key = "hieKedq";
int turn_tcp_po = 1;
char* realmstr = "lul.org";
bool is_turn_tcp = true;
int allocation_lifetime = 1800;
int restricted_bandwidth = 10;
int bandwidth_per_allocation = 150;
int max_relay_per_username = 5;

#define SOFTWARE_DESCRIPTION "TurnServer 1"  

//*******************Coturn**********************************************
int can_resume = 1;
bool secure_stun = true;
bool stun_only = false;
bool no_stun = false;
#define MAX_NUMBER_OF_UNKNOWN_ATTRS (128)
//********************************************************************
socketListener manager(8888);
turn_server::turn_server()
{
}

turn_server::~turn_server()
{
}

int turn_server::StartServer() {
	manager.onTcpconnected += newDelegate(this, &turn_server::onTcpConnect);

	manager.onTcpReciveData += newDelegate(this, &turn_server::onTcpMessage);

	manager.onUdpReciveData += newDelegate(this, &turn_server::onUdpMessage);
	manager.StartSocketListen();
	return 1;
}
void turn_server::onTcpConnect(tcp_socket* tcpsocket) {

	printf("收到tcp连接");
}

void turn_server::onTcpMessage(buffer_type* buf, int lenth, tcp_socket* tcpsocket) {
	//boost::asio::posix 
	//address_type remoteaddr = address_type(tcpsocket->remote_endpoint().address());
	//address_type localaddr = address_type(tcpsocket->local_endpoint().address());
	//int remoteAddrSize = tcpsocket->local_endpoint().size();
	MessageHandle_new(*buf, lenth, TCP_SOCKET, tcpsocket);
	/*int method = turn_agreement::stun_get_method_str(buf, lenth);*/
	printf("收到tcp消息");
}

void turn_server::onUdpMessage(buffer_type* buf, int lenth, udp_socket* udpsocket) {
	//address_type remoteaddr = address_type(udpsocket->remote_endpoint().address());
	//address_type localaddr = address_type(udpsocket->local_endpoint().address());
	//int remoteAddrSize = udpsocket->local_endpoint().size();
	MessageHandle_new(*buf, lenth, UDP_SOCKET, udpsocket);
	printf("收到udp消息");
}


int turn_server::MessageHandle_new(buffer_type buf, int lenth, SOCKET_TYPE socket_type, socket_base* sock)
{
	stun_tid tid;
	size_t blen = lenth;
	size_t orig_blen = lenth;

	int error_code = 0;
	const u08bits *reason = NULL;
	size_t counter = 0;

	u16bits chnum = 0;
	const u08bits* in_data = (const u08bits*)buf;
	u16bits ua_num = 0;//unknow_attribute_number
	bool no_response = false;//是否需要创建responese，默认需要创建
	bool resp_constructed = false;//是否创建了response

	ioa_network_buffer_handle out_io_handle = (ioa_network_buffer_handle)malloc(sizeof(ioa_network_buffer_handle));
	userSessionsManager userSessionsManager;
	useressionEntity* userSession = userSessionsManager.getClientSession(socket_type, sock);
	if (stun_is_channel_message_str(in_data, &blen, &chnum, 1)) {
		//处理channel消息
		return 1;
	}
	//判断消息是否完整
	if (!stun_is_command_message_full_check_str(in_data, lenth, 0, &userSession->enforce_fingerprints))
	{
		return -1;
	}

	//完整消息处理： 
	u16bits method = stun_get_method_str(in_data, lenth);
	stun_tid_from_message_str(in_data, lenth, &tid);
	if (method != STUN_METHOD_BINDING)
	{
		no_response = true;
	}
	if (stun_is_request_str(in_data, lenth))
	{
		if (method == STUN_METHOD_BINDING && no_stun == true)
		{
			no_response = true;
		}
		else if (method != STUN_METHOD_BINDING && stun_only == true)
		{
			no_response = true;
		}
		else if (method != STUN_METHOD_BINDING || secure_stun == true)
		{
			if (method == STUN_METHOD_ALLOCATE)
			{
				dealAllocation(method, &out_io_handle, &resp_constructed, socket_type, sock, &tid, &error_code, reason, &counter);
			}
			if (userSession->origin_set == true) {

			}
			if (!error_code&&userSession->origin_set == false && method == STUN_METHOD_ALLOCATE) {
				stun_attr_ref sar = stun_attr_get_first_str(in_data, lenth);
				 

			}
			if (!error_code&&resp_constructed == false && no_response == false) {

			}
		}
		if (error_code != 0 && resp_constructed == false && no_response == false)
		{
		}
	}
	else if (stun_is_indication_str(in_data, lenth))
	{
		no_response = true;
	}
	else
	{

	}
	//存在unknow_attribbute
	if (ua_num > 0) {

	}
	//需要创建response
	if (no_response == false) {


	}
	else {
		resp_constructed = false;
	}
}

int turn_server::check_stun_auth(buffer_type buf, int lenth)
{
	u08bits usname[STUN_MAX_USERNAME_SIZE + 1];
	u08bits nonce[STUN_MAX_NONCE_SIZE + 1];
	u08bits realm[STUN_MAX_REALM_SIZE + 1];
	size_t alen = 0;
	int new_nonce = 0;
	{
		int generate_new_nonce = 0;
	}
}

bool turn_server::dealAllocation(u16bits method, ioa_network_buffer_handle* out_io_handle, bool* resp_constructed,
	SOCKET_TYPE socket_type, socket_base * sock,
	stun_tid* currentTid, int* errorCode, const u08bits *reason, size_t* counter)
{
	allocation alloc(socket_type, sock);
	if (alloc.is_valid == true)
	{
		if (!stun_tid_equals(&(alloc.tid), currentTid))
		{
			*errorCode = 437;
			reason = (const u08bits *)"Mismatched allocation: wrong transaction ID";
		}
		if ((*errorCode))
		{
			return true;
		}
		turn_server_addrs_list_t *asl = NULL;////备用服务列表 
		if (asl && asl->size)
		{
			ioa_addr* serveraddr = (ioa_addr*)malloc(sizeof(ioa_addr));

			if (socket_type == UDP_SOCKET) {
				udp_socket* udp_sock = (udp_socket*)sock;
				make_ioa_addr((const u08bits*)udp_sock->local_endpoint().address().to_string().data(), udp_sock->remote_endpoint().port(), serveraddr);
			}
			else if (socket_type == TCP_SOCKET) {
				tcp_socket* tcp_sock = (tcp_socket*)sock;
				make_ioa_addr((const u08bits*)tcp_sock->local_endpoint().address().to_string().data(), tcp_sock->remote_endpoint().port(), serveraddr);
			}
			set_alternate_server(asl, serveraddr, counter, method, currentTid, resp_constructed, errorCode, &reason, out_io_handle);
		}
	}
}


void turn_server::set_alternate_server(turn_server_addrs_list_t *asl, const ioa_addr *local_addr, size_t *counter,
	u16bits method, stun_tid *tid, bool* resp_constructed, int *err_code,
	const u08bits **reason, ioa_network_buffer_handle nbh)
{
	commonMethod commonMthod;
	if (asl && asl->size && local_addr) {

		size_t i;

		/* to prevent indefinite cycle: */

		for (i = 0; i < asl->size; ++i) {
			ioa_addr *addr = &(asl->addrs[i]);
			if (addr_eq(addr, local_addr))
				return;
		}

		for (i = 0; i < asl->size; ++i) {
			if (*counter >= asl->size)
				*counter = 0;
			ioa_addr *addr = &(asl->addrs[*counter]);
			*counter += 1;
			if (addr->ss.sa_family == local_addr->ss.sa_family) {

				*err_code = 300;

				size_t len = commonMthod.ioa_network_buffer_get_size(nbh);
				stun_init_error_response_str(method, commonMthod.ioa_network_buffer_data(nbh), &len, *err_code, *reason, tid);
				*resp_constructed = true;
				stun_attr_add_addr_str(commonMthod.ioa_network_buffer_data(nbh), &len, STUN_ATTRIBUTE_ALTERNATE_SERVER, addr);
				commonMthod.ioa_network_buffer_set_size(nbh, len);

				return;
			}
		}
	}
}