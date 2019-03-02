#include "socketListener.h"
 


#ifndef SERVERPORT
#define SERVERPORT 8888
#endif // !1

#ifndef MAXBYTES
#define MAXBYTES 4096 
#endif // !1


static struct event_base * base;

socketListener::socketListener()
{
}


socketListener::~socketListener()
{
}

void socketListener::StartSocketListen() {
	//int serverfd;
	socklen_t serveraddrlen;
	struct sockaddr_in serveraddr;
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(SERVERPORT);
	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
	 //serverfd = socket(AF_INET, SOCK_DGRAM, 0);
	serveraddrlen = sizeof(serveraddr);
	_startloop(&serveraddr);
}

void socketListener::_startloop(struct sockaddr_in* addr) {
	base = event_base_new();

	evconnlistener *evcon = evconnlistener_new_bind(base, accept_cb, (void*)base, LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, 128, (struct sockaddr*)addr, sizeof(struct sockaddr_in));

	event_base_dispatch(base);
	evconnlistener_free(evcon);
	event_base_free(base);
}

void  accept_cb(struct evconnlistener *listener, evutil_socket_t clientfd, struct sockaddr *addr, int len, void *arg)
{
	struct event_base* base = (struct event_base*)arg;
	puts("Accept client connect");

	evutil_make_socket_nonblocking(clientfd);
	bufferevent* bev = bufferevent_socket_new(base, clientfd, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	bufferevent_setcb(bev, _read_buf_cb, _write_buf_cb, _event_cb, NULL);

	struct timeval timeout_read = { 10, 0 };
	bufferevent_set_timeouts(bev, &timeout_read, NULL);
	bufferevent_setwatermark(bev, EV_READ, 10, 0);
	bufferevent_setwatermark(bev, EV_WRITE, 10, 0);
	bufferevent_enable(bev, EV_READ | EV_WRITE);
}




void  _read_buf_cb(struct bufferevent* bev, void* cbarg)
{
	int ret;
	char buf[MAXBYTES];
	ret = bufferevent_read(bev, buf, sizeof(buf));
	write(STDOUT_FILENO, buf, ret);
}

void  _write_buf_cb(struct bufferevent* bev, void* cbarg)
{
	printf("%s\n", __FUNCTION__);
}

void  _event_cb(struct bufferevent* bev, short event, void* cbarg)
{
	if (BEV_EVENT_READING & event)
		puts("BEV_EVENT_READING");

	if (BEV_EVENT_WRITING & event)
		puts("BEV_EVENT_WRITING");

	if (BEV_EVENT_ERROR & event)
		puts("BEV_EVENT_ERROR");

	if (BEV_EVENT_EOF & event)
	{
		puts("BEV_EVENT_EOF");
		bufferevent_free(bev);
	}
	if (BEV_EVENT_TIMEOUT & event)
	{
		puts("BEV_EVENT_TIMEOUT");
		bufferevent_free(bev);
	}
}