#pragma once
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
//////////// 
#include "myDeletegate.h"
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

using namespace boost::asio;
using namespace std;
  
typedef  char buffer_type[4096];

typedef ip::tcp::socket tcp_socket;
typedef ip::udp::socket udp_socket;


 
