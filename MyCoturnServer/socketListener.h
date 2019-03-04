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

typedef ip::address address_type;
typedef boost::shared_ptr<tcp_socket> sock_ptr;
  

class socketListener
{

public:
 
	socketListener(int port);
	~socketListener();
	void StartSocketListen();

	void accept_tcp();

	void accept_handler(const boost::system::error_code & ec, sock_ptr sock);

	void tcp_write_handler(const boost::system::error_code & ec);

 

 
	 

	void tcp_read_handler(const boost::system::error_code & ec, sock_ptr sock);

	void accept_udp();

	void udp_hand_receive(const boost::system::error_code & error, std::size_t size);

	void udp_hand_send(boost::shared_ptr<std::string> message, const boost::system::system_error & error, std::size_t size);
	  
	

};

 
