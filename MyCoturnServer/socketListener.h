#pragma once

#include "commonTypes.h"

 

class socketListener
{

public:

	socketListener(int port);
	~socketListener();


private:        void accept_tcp();

private:		void accept_handler(const boost::system::error_code & ec, sock_ptr sock);

private:		void read_tcp(sock_ptr sock);

private:		void tcp_read_handler(const boost::system::error_code & ec, sock_ptr sock, std::size_t size, buffer_type buf);
				 
private:        void tcp_write_handler(const boost::system::error_code & ec);




		    

private:	void accept_udp();

private:	void udp_hand_receive(const boost::system::error_code & error, std::size_t size, buffer_type buf);

private:	void udp_hand_send(boost::shared_ptr<std::string> message, const boost::system::system_error & error, std::size_t size);

public:  	void StartSocketListen();

public: 	void WhileTcpConnect(void(*func)(sock_ptr *));

public: 	void WhileTcpMessage(void(*func)(buffer_type*, int, sock_ptr *));

public: 	void WhileUdpMessage(void(*func)(buffer_type*, int, udp_endpoint *));























};


