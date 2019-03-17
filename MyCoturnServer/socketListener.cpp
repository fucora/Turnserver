#include "socketListener.h"





socketListener::socketListener(int port)
{
	serverport = port;
}


socketListener::~socketListener()
{
}


//********************************TCP listen****************************************************************************************
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
		onTcpconnected(sock.get());
	}
	catch (const std::exception&)
	{
	}

	try
	{
		read_tcp(sock);
	}
	catch (const std::exception&)
	{
	}

	// 发送完毕后继续监听，否则io_service将认为没有事件处理而结束运行
	accept_tcp();
}


void socketListener::read_tcp(sock_ptr sock)
{
	sock.get()->async_read_some(
		buffer(tcp_buffer),
		boost::bind(
			&socketListener::tcp_read_handler,
			this,
			boost::asio::placeholders::error,
			sock,
			boost::asio::placeholders::bytes_transferred,
			tcp_buffer
		)
	);
}

void socketListener::tcp_read_handler(const boost::system::error_code&ec, sock_ptr sock, std::size_t size, buffer_type buf)
{
	try
	{
		if (size < 1) {
			return;
		}

		buffer_type linshbuf;
		memcpy(linshbuf, buf, size); //拷贝到新的数组中 
		onTcpReciveData(&linshbuf, (int)size, sock.get()); 

	}
	catch (const std::exception&)
	{

	}
	read_tcp(sock);
}

void socketListener::tcp_write_handler(const boost::system::error_code&ec)
{
	cout << "send msg complete" << endl;
}


//********************************UDP listen****************************************************************************************
void socketListener::accept_udp()
{
	udp_listener->async_receive_from(buffer(udp_buffer), udp_remot_endpoint,
		boost::bind(&socketListener::udp_hand_receive,
			this,
			boost::asio::placeholders::error,
			udp_listener,
			boost::asio::placeholders::bytes_transferred,
			udp_buffer
		));
}
void socketListener::udp_hand_receive(const boost::system::error_code& error, udp_socket* sock, std::size_t size, buffer_type buf)
{
	if (error) {
		return;
	}
	try
	{ 
		if (size < 1) {
			return;
		}

		buffer_type linshbuf;
		memcpy(linshbuf, buf, size); //拷贝到新的数组中 
		onUdpReciveData(&linshbuf, (int)size, sock);

	}
	catch (const std::exception&)
	{

	}
	accept_udp();//next client;

}

void socketListener::udp_hand_send(boost::shared_ptr<std::string> message, const boost::system::system_error& error, std::size_t size)
{

}
//***********************************public method*******************************************************
void socketListener::StartSocketListen() {
	tcp_listener = new ip::tcp::acceptor(m_io, tcp_endpoint(ip::tcp::v4(), serverport));
	udp_listener = new ip::udp::socket(m_io, udp_endpoint(ip::udp::v4(), serverport));

	accept_tcp();
	accept_udp();
	m_io.run();
}



