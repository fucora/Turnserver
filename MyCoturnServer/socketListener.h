#pragma once
#include <iostream>
#include <memory>
#include <array>

#include <boost/shared_ptr.hpp>
#include <boost/asio.hpp>
#include <boost/asio/placeholders.hpp>
#include <boost/system/error_code.hpp>
#include <boost/bind/bind.hpp> 
#include <boost/enable_shared_from_this.hpp>
#include <boost/signal.hpp>

using namespace boost::asio;
using namespace std;

typedef ip::tcp::socket tcp_socket;
typedef ip::udp::socket udp_socket;
typedef ip::tcp::endpoint tcp_endpoint;
typedef ip::udp::endpoint udp_endpoint;

typedef ip::address address_type;
typedef boost::shared_ptr<tcp_socket> sock_ptr;


class socketListener
{

public:

	socketListener(int port);
	~socketListener();


private:    void accept_tcp();

private:   void accept_handler(const boost::system::error_code & ec, sock_ptr sock);

private:   void tcp_write_handler(const boost::system::error_code & ec);






private:	void tcp_read_handler(const boost::system::error_code & ec, sock_ptr sock);

private:	void accept_udp();

private:	void udp_hand_receive(const boost::system::error_code & error, std::size_t size);

private:	void udp_hand_send(boost::shared_ptr<std::string> message, const boost::system::system_error & error, std::size_t size);

public:  	void StartSocketListen();

	 
			void WhileTcpConnect(void(*func)(tcp_endpoint *));
			void WhileTcpMessage(void(*func)(char[], tcp_endpoint *));

			void WhileUdpMessage(void(*func)(char[], udp_endpoint *));


			 
			 

};


