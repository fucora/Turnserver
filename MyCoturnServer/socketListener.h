#pragma once
#include <iostream>
#include <memory>
#include <array>

#include <boost/shared_ptr.hpp>
#include <boost/asio.hpp>
#include <boost/asio/placeholders.hpp>
#include <boost/system/error_code.hpp>
#include <boost/bind/bind.hpp>

using namespace boost::asio;
using namespace std;
 
typedef ip::tcp::socket socket_type;
typedef ip::address address_type;
typedef boost::shared_ptr<socket_type> sock_ptr;

class socketListener
{

public:
	socketListener();	
	~socketListener();
	void StartSocketListen();

	void accept();

	void accept_handler(const boost::system::error_code & ec, sock_ptr sock);

	void write_handler(const boost::system::error_code & ec);

 

	

};

 
