#pragma once
#include <cstdio>  
#include <stdint.h>
#include <iostream>
#include <memory>
#include <array>
#include <netinet/in.h>
////////////
#include "../common/ns_turn_msg.h"
#include "../common/ns_turn_server.h"
#include "../ns_turn_defs.h"
#include "../common/ns_turn_msg_defs.h"
////////
#include <boost/shared_ptr.hpp>
#include <boost/asio.hpp>
#include <boost/asio/placeholders.hpp>
#include <boost/system/error_code.hpp>
#include <boost/bind/bind.hpp> 
#include <boost/enable_shared_from_this.hpp>
#include <boost/signals2.hpp> 

using namespace boost::asio;
using namespace std;


typedef  char buffer_type[4096];

typedef ip::tcp::socket tcp_socket;
typedef ip::udp::socket udp_socket;
typedef ip::tcp::endpoint tcp_endpoint;
typedef ip::udp::endpoint udp_endpoint;

typedef ip::address address_type;
typedef boost::shared_ptr<tcp_socket> sock_ptr;
 
