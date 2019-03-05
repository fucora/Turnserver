#pragma once

 

void onTcpConnect(sock_ptr * remote_endpoint);

void onTcpMessage(sihnalbuffer data, sock_ptr * remote_endpoint);

void onUdpMessage(sihnalbuffer data, udp_endpoint * remote_endpoint);
