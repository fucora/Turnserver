#pragma once
#ifndef COMMONTYPES_H
#define COMMONTYPES_H

#include <cstdio>  
#include <stdint.h>
#include <iostream>
#include <memory>
#include <array>
#include <netinet/in.h>
#include <list>
#include <functional> 
#include <string>
#include <algorithm>
#include <time.h>
#include <sys/time.h>
#include <malloc.h>
#include <stdint.h>
#include <sys/types.h> 
#include <vector>
/////////////////// 
#include "Coturn/ns_turn_defs.h" 
#include "Coturn/common/ns_turn_ioalib.h"
#include "Coturn/common/ns_turn_msg.h" 
#include "Coturn/common/ns_turn_khash.h"
#include "Coturn/common/stun_buffer.h"
/////////////
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
////////
#include <boost/shared_ptr.hpp>
#include <boost/asio.hpp>
#include <boost/asio/placeholders.hpp>
#include <boost/system/error_code.hpp>
#include <boost/bind/bind.hpp> 
 
#include <boost/enable_shared_from_this.hpp>
#include <boost/signals2.hpp>  
#include <boost/utility/result_of.hpp>
#include <boost/typeof/typeof.hpp>
#include <boost/assign.hpp>
#include <boost/ref.hpp>
#include <boost/function.hpp>  
#include <boost/asio/basic_socket.hpp>
#include <boost/serialization/utility.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/export.hpp> 
#include <boost/serialization/serialization.hpp>
#include <boost/serialization/access.hpp> 
#include <boost/serialization/map.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/serialization/binary_object.hpp>
 
using namespace boost::asio;
using namespace std;

typedef char buffer_type[4096];
typedef ip::tcp::endpoint tcp_endpoint;
typedef ip::udp::endpoint udp_endpoint;
typedef ip::tcp::socket tcp_socket;
typedef ip::udp::socket udp_socket;
typedef ip::address address_type; 

 
struct _turn_server_addrs_list {
	ioa_addr *addrs;
	volatile size_t size;
	turn_mutex m;
};

typedef struct _turn_server_addrs_list turn_server_addrs_list_t;

#endif