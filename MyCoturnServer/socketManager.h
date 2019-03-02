#pragma once
class socketManager
{
public:
	socketManager();
	~socketManager();
};

void StartListen();

static int init_new_client(int client_fd);

static int remove_client(int client_fd);

static int get_max_fd(int fd);

void StartUdpClient();
