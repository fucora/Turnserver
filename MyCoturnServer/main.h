#pragma once

 

void onTcpConnect(sock_ptr * remote_endpoint);

void onTcpMessage(buffer_type data, int lenth, sock_ptr * remote_endpoint);

void onUdpMessage(buffer_type data, int lenth, udp_endpoint * remote_endpoint);
