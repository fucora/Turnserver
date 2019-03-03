#include "socketListener.h"



#ifndef BLOCK_SIZE
#define BLOCK_SIZE 4096;
#endif // !BLOCK_SIZE

int serverport = 8888;

io_service m_io;
ip::tcp::acceptor* m_acceptor;

socketListener::socketListener() 
{ 

}


socketListener::~socketListener()
{
}

void socketListener::StartSocketListen() { 
	m_acceptor = new ip::tcp::acceptor(m_io, ip::tcp::endpoint(ip::tcp::v4(), serverport));
	m_io.run();
}


void socketListener::accept()
{
	sock_ptr sock(new socket_type(m_io));
	m_acceptor->async_accept(*sock, boost::bind(&socketListener::accept_handler, this, boost::asio::placeholders::error, sock));
}

void socketListener::accept_handler(const boost::system::error_code& ec, sock_ptr sock)
{
	if (ec)
	{
		return;
	}

	sock->async_write_some(buffer("hello asio"), boost::bind(&socketListener::write_handler, this, boost::asio::placeholders::error));
	// 发送完毕后继续监听，否则io_service将认为没有事件处理而结束运行
	accept();
}

void socketListener::write_handler(const boost::system::error_code&ec)
{
	cout << "send msg complete" << endl;
}
