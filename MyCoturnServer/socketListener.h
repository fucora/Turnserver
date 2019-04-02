#pragma once

#include "commonTypes.h"



class socketListener
{
	typedef boost::shared_ptr<tcp_socket> sock_ptr;

private:	int serverport = 8888;
private:	io_service m_io;
private:	ip::tcp::acceptor* tcp_listener;
private:	buffer_type tcp_buffer;

private:	udp_socket* udp_listener;
private:	udp_endpoint udp_remot_endpoint;
private:	buffer_type udp_buffer;
			//第一个void是返回值类型
public:     CMultiDelegate<void, tcp_socket*> onTcpconnected;
public:  	CMultiDelegate<void, buffer_type*, int, tcp_socket*> onTcpReciveData;
public:  	CMultiDelegate<void, buffer_type*, int, udp_socket*> onUdpReciveData;


public:

	socketListener(int port);
	~socketListener();




private:        void accept_tcp();

private:		void accept_handler(const boost::system::error_code & ec, sock_ptr sock);

private:		void read_tcp(sock_ptr sock);

private:		void tcp_read_handler(const boost::system::error_code & ec, sock_ptr sock, std::size_t size, buffer_type buf);

private:        void tcp_write_handler(const boost::system::error_code & ec);






private:	void accept_udp();

private:	void udp_hand_receive(const boost::system::error_code & error, udp_socket * sock, std::size_t size, buffer_type buf);



private:	void udp_hand_send(boost::shared_ptr<std::string> message, const boost::system::system_error & error, std::size_t size);


public:  	void StartSocketListen();

public:			int udp_send(char * senddata, udp_socket * udpsocket);

public:			int tcp_send(char * senddata, tcp_socket * tcpsocket);
 





























};


