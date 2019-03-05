#include "socketListener.h"


int serverport = 8888;

io_service m_io;
ip::tcp::acceptor* tcp_listener;
buffer_type tcp_buffer;

udp_socket* udp_listener;
udp_endpoint udp_remot_endpoint;
buffer_type udp_buffer;

boost::signals2::signal<void(sock_ptr*)> _tcpconnectCallback;
boost::signals2::signal<void(buffer_type, int, sock_ptr*)> _tcpReciveDataCallback;
boost::signals2::signal<void(buffer_type, int, udp_endpoint*)> _udpReciveDataCallback;

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

void socketListener::read_tcp(sock_ptr sock)
{
	sock.get()->async_read_some(
		buffer(tcp_buffer),
		boost::bind(
			&socketListener::tcp_read_handler, this,
			boost::asio::placeholders::error,
			sock
		)
	);
}

void socketListener::accept_handler(const boost::system::error_code& ec, sock_ptr sock)
{
	if (ec)
	{
		return;
	}

	try
	{
		_tcpconnectCallback(&sock);
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

void socketListener::tcp_write_handler(const boost::system::error_code&ec)
{
	cout << "send msg complete" << endl;
}

void socketListener::tcp_read_handler(const boost::system::error_code&ec, sock_ptr sock)
{
	try
	{
		_tcpReciveDataCallback(tcp_buffer,sizeof(tcp_buffer), &sock);
		 
	}
	catch (const std::exception&)
	{

	}
	read_tcp(sock);
}
//********************************UDP listen****************************************************************************************
void socketListener::accept_udp()
{
	udp_listener->async_receive_from(buffer(udp_buffer), udp_remot_endpoint, boost::bind(&socketListener::udp_hand_receive, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
}
void socketListener::udp_hand_receive(const boost::system::error_code& error, std::size_t size)
{
	if (error) {
		return;
	}
	try
	{
		_udpReciveDataCallback(udp_buffer, sizeof(udp_buffer), &udp_remot_endpoint);

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

void socketListener::WhileTcpConnect(void(*func)(sock_ptr*)) {
	_tcpconnectCallback.connect(_tcpconnectCallback.num_slots(), func);
}
void socketListener::WhileTcpMessage(void(*func)(buffer_type, int, sock_ptr*)) {
	_tcpReciveDataCallback.connect(_tcpReciveDataCallback.num_slots(), func);
}

void socketListener::WhileUdpMessage(void(*func)(buffer_type, int, udp_endpoint*)) {
	_udpReciveDataCallback.connect(_udpReciveDataCallback.num_slots(), func);
}

