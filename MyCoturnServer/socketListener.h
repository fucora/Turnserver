#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>

class socketListener
{

public:
	socketListener();
	~socketListener();

	void StartSocketListen();
	void _startloop(sockaddr_in * addr);
	

};



void accept_cb(evconnlistener * listener, evutil_socket_t clientfd, sockaddr * addr, int len, void * arg);

void _read_buf_cb(bufferevent * bev, void * cbarg);

void _write_buf_cb(bufferevent * bev, void * cbarg);

void _event_cb(bufferevent * bev, short event, void * cbarg);
