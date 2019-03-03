#include "socketListener.h"



#ifndef BLOCK_SIZE
#define BLOCK_SIZE 4096;
#endif // !BLOCK_SIZE

int serverport = 8888;

io_service m_io;
ip::tcp::acceptor* tcp_listener;
char   tcp_buffer[4096];


ip::udp::socket* udp_listener;
ip::udp::endpoint remot_endpoint_;
char udp_buffer[4096];

socketListener::socketListener()
{
}


socketListener::~socketListener()
{
}

void socketListener::StartSocketListen() {
	tcp_listener = new ip::tcp::acceptor(m_io, ip::tcp::endpoint(ip::tcp::v4(), serverport));
	udp_listener = new ip::udp::socket(m_io, ip::udp::endpoint(ip::udp::v4(), serverport));

	accept_tcp();
	accept_udp();
	m_io.run();
}


void socketListener::accept_tcp()
{
	sock_ptr tcp_dataInfo(new tcp_socket(m_io));
	tcp_listener->async_accept(*tcp_dataInfo, boost::bind(&socketListener::accept_handler, this, boost::asio::placeholders::error, tcp_dataInfo));
}

void socketListener::accept_handler(const boost::system::error_code& ec, sock_ptr sock)
{
	if (ec)
	{
		return;
	}
	try
	{ 
		//sock.get()->async_read_some(boost::asio::buffer(tcp_buffer),);
		sock.get()->async_read_some(
			boost::asio::buffer(tcp_buffer),
			boost::bind(
				&socketListener::read_handler, this,
				boost::asio::placeholders::error,
				sock
			)
		);
	}
	catch (const std::exception&)
	{

	}

	// 发送完毕后继续监听，否则io_service将认为没有事件处理而结束运行
	accept_tcp();
}

void socketListener::write_handler(const boost::system::error_code&ec)
{
	cout << "send msg complete" << endl;
}

void socketListener::read_handler(const boost::system::error_code&ec, sock_ptr sock)
{
	cout << "send msg complete" << endl;
	sock.get()->async_read_some(
		boost::asio::buffer(tcp_buffer),
		boost::bind(
			&socketListener::read_handler, this,
			boost::asio::placeholders::error,
			sock
		)
	);
}
//---------------------------------------------------------------------------------------------------------------------
void socketListener::accept_udp()
{
	udp_listener->async_receive_from(boost::asio::buffer(udp_buffer), remot_endpoint_, boost::bind(&socketListener::hand_receive, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
}
void socketListener::hand_receive(const boost::system::error_code& error, std::size_t size)
{
	if (error) {
		return;
	}
	try
	{
		//数据
		auto data = udp_buffer;
	}
	catch (const std::exception&)
	{

	}
	accept_udp();//next client;

}

void socketListener::hand_send(boost::shared_ptr<std::string> message, const boost::system::system_error& error, std::size_t size)
{

}
