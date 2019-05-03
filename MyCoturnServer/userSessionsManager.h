#pragma once
#ifndef SERVERSMANAGER_H
#define SERVERSMANAGER_H

#include "commonTypes.h"
using namespace std;

struct useressionEntity
{
	bool origin_set = false;
	int enforce_fingerprints = false;
	s08bits origin[STUN_MAX_ORIGIN_SIZE + 1];


	bool is_valid = false;
	stun_tid tid;


	int client_socket_port = 0;
	u08bits* client_socket_addr = NULL;
};


class userSessionsManager
{

public:
	userSessionsManager();
	~userSessionsManager();

	useressionEntity* getClientSession(SOCKET_TYPE socket_type, socket_base * sock);

private: static vector<useressionEntity> userSessions;
};

#endif // ! SERVERSMANAGER_H
