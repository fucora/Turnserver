#pragma once

void onTcpConnect(tcp_endpoint * remote_endpoint);

void onTcpMessage(char data[], tcp_endpoint * remote_endpoint);

void onUdpMessage(char data[], udp_endpoint * remote_endpoint);
