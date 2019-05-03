#pragma once
#ifndef SERVERSMANAGER_H
#define SERVERSMANAGER_H

#include "commonTypes.h"
using namespace std;

struct useressionEntity
{
	bool origin_set = false;
	int enforce_fingerprints = false;

	int client_socket_port = 0;
	u08bits* client_socket_addr = NULL;
};


class userSessionsManager
{

public:
	userSessionsManager();
	~userSessionsManager();

	useressionEntity* getClientSession(SOCKET_TYPE socket_type, socket_base * sock);

private: static vector<useressionEntity> serverSessions;
};

#endif // ! SERVERSMANAGER_H
