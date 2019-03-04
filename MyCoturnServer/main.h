#pragma once

 

void onTcpConnect(sock_ptr * remote_endpoint);

void onTcpMessage(char data[], sock_ptr * remote_endpoint);

void onUdpMessage(char data[], udp_endpoint * remote_endpoint);
