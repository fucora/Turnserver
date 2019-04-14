﻿/*
 *  TurnServer - TURN server implementation.
 *  Copyright (C) 2008-2009 Sebastien Vincent <sebastien.vincent@turnserver.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL.  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so.  If you
 *  do not wish to do so, delete this exception statement from your
 *  version.  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

 /**
  * \file allocation.c
  * \brief Allocation between TURN client and external(s) client(s).
  * \author Sebastien Vincent
  * \date 2008-2010
  */


#include "allocation.h"


struct allocation_desc* allocation_list_find_tuple(struct list_head* list, int transport_protocol, socket_base* sock)
{
	uint8_t* client_addr = NULL; /**< Client address */
	size_t client_addr_size = 0;
	unsigned short client_port = 0;

	uint8_t* server_addr = NULL; /**< Server address */
	size_t server_addr_size = 0;
	unsigned short server_port = 0;

	if (transport_protocol == IPPROTO_UDP)
	{
		udp_socket* sockeet = ((udp_socket*)sock);
		client_addr = (uint8_t*)malloc(sockeet->remote_endpoint().address().to_string().size());
		memcpy(client_addr, sockeet->remote_endpoint().address().to_string().data(), sockeet->remote_endpoint().address().to_string().size());
		client_port = sockeet->remote_endpoint().port();

		server_addr = (uint8_t*)malloc(sockeet->local_endpoint().address().to_string().size());
		memcpy(server_addr, sockeet->local_endpoint().address().to_string().data(), sockeet->local_endpoint().address().to_string().size());
		server_port = sockeet->local_endpoint().port();
	}
	else
	{
		tcp_socket* sockeet = ((tcp_socket*)sock);
		client_addr = (uint8_t*)malloc(sockeet->remote_endpoint().address().to_string().size());
		memcpy(client_addr, sockeet->remote_endpoint().address().to_string().data(), sockeet->remote_endpoint().address().to_string().size());
		client_port = sockeet->remote_endpoint().port();

		server_addr = (uint8_t*)malloc(sockeet->local_endpoint().address().to_string().size());
		memcpy(server_addr, sockeet->local_endpoint().address().to_string().data(), sockeet->local_endpoint().address().to_string().size());
		server_port = sockeet->local_endpoint().port();
	}
	debug(DBG_ATTR, "查找客户端五元组:地址：%s,端口：%d ", client_addr, client_port);
	struct list_head* get = NULL;
	struct list_head* n = NULL;

	list_iterate_safe(get, n, list)
	{
		struct allocation_desc* tmp = list_get(get, struct allocation_desc, list);
		if (tmp->tuple.transport_protocol == transport_protocol &&
			memcmp(&tmp->tuple.client_addr, client_addr, client_addr_size)==0 && 
			tmp->tuple.client_port == client_port && 
			memcmp(&tmp->tuple.server_addr, server_addr, server_addr_size)==0 && 
			tmp->tuple.server_port == server_port)
		{
			debug(DBG_ATTR, "---找到了 \n");
			return tmp;
		}
	}
	debug(DBG_ATTR, "---没找到 \n");
	/* not found */
	return NULL;
}

struct allocation_channel* allocation_desc_find_channel_number(struct allocation_desc* desc, uint16_t channel)
{
	struct list_head* get = NULL;
	struct list_head* n = NULL;

	list_iterate_safe(get, n, &desc->peers_channels)
	{
		struct allocation_channel* tmp = list_get(get, struct allocation_channel, list);

		if (tmp->channel_number == channel)
		{
			return tmp;
		}
	}

	/* not found */
	return 0;
}

uint32_t allocation_desc_find_channel(struct allocation_desc* desc, int family, const uint8_t* peer_addr, uint16_t peer_port)
{
	struct list_head* get = NULL;
	struct list_head* n = NULL;
	list_iterate_safe(get, n, &desc->peers_channels)
	{
		struct allocation_channel* tmp = list_get(get, struct allocation_channel, list);
		if (tmp->family == family && !memcmp(&tmp->peer_addr, peer_addr,
			family == AF_INET ? 4 : 16) && tmp->peer_port == peer_port)
		{
			return tmp->channel_number;
		}
	}
	/* not found */
	return 0;
}

void allocation_channel_set_timer(struct allocation_channel* channel, uint32_t lifetime)
{
	struct itimerspec expire;
	struct itimerspec old;

	/* timer */
	expire.it_value.tv_sec = (long)lifetime;
	expire.it_value.tv_nsec = 0;
	expire.it_interval.tv_sec = 0; /* no interval */
	expire.it_interval.tv_nsec = 0;
	memset(&old, 0x00, sizeof(struct itimerspec));

	/* set the timer */
	if (timer_settime(channel->expire_timer, 0, &expire, &old) == -1)
	{
		return;
	}
}

int allocation_desc_add_channel(struct allocation_desc* desc, uint16_t channel, uint32_t lifetime, int family, const uint8_t* peer_addr, uint16_t peer_port)
{
	struct allocation_channel* ret = NULL;
	struct sigevent event;

	if (!(ret = (allocation_channel*)malloc(sizeof(struct allocation_channel))))
	{
		return -1;
	}

	ret->family = family;
	memcpy(&ret->peer_addr, peer_addr, family == AF_INET ? 4 : 16);
	ret->peer_port = peer_port;
	ret->channel_number = channel;

	/* timer */
	memset(&event, 0x00, sizeof(struct sigevent));
	event.sigev_value.sival_ptr = ret;
	event.sigev_notify = SIGEV_SIGNAL;
	event.sigev_signo = SIGRT_EXPIRE_CHANNEL;

	memset(&ret->expire_timer, 0x00, sizeof(timer_t));
	if (timer_create(CLOCK_REALTIME, &event, &ret->expire_timer) == -1)
	{
		free(ret);
		return -1;
	}

	allocation_channel_set_timer(ret, lifetime);

	/* add to the list */
	LIST_ADD(&ret->list, &desc->peers_channels);
	INIT_LIST(ret->list2);
	return 0;
}

struct allocation_permission* allocation_desc_find_permission(struct allocation_desc* desc, int family, const uint8_t* peer_addr)
{
	struct list_head* get = NULL;
	struct list_head* n = NULL;

	list_iterate_safe(get, n, &desc->peers_permissions)
	{
		struct allocation_permission* tmp = list_get(get, struct allocation_permission, list);

		/* check only the network address (not the port) */
		if (tmp->family != family)
		{
			continue;
		}

		if (tmp->family == family && !memcmp(tmp->peer_addr, peer_addr, family == AF_INET ? 4 : 16))
		{
			return tmp;
		}
	}
	/* not found */
	return NULL;
}

int allocation_desc_add_permission(struct allocation_desc* desc, uint32_t lifetime, int family, const uint8_t* peer_addr)
{
	struct allocation_permission* ret = NULL;
	struct sigevent event;

	if (!(ret = (allocation_permission*)malloc(sizeof(struct allocation_permission))))
	{
		return -1;
	}

	ret->family = family;
	memcpy(&ret->peer_addr, peer_addr, family == AF_INET ? 4 : 16);

	/* timer */
	memset(&event, 0x00, sizeof(struct sigevent));
	event.sigev_value.sival_ptr = ret;
	event.sigev_notify = SIGEV_SIGNAL;
	event.sigev_signo = SIGRT_EXPIRE_PERMISSION;

	memset(&ret->expire_timer, 0x00, sizeof(timer_t));
	if (timer_create(CLOCK_REALTIME, &event, &ret->expire_timer) == -1)
	{
		free(ret);
		return -1;
	}

	allocation_permission_set_timer(ret, lifetime);
	/* add to the list */
	LIST_ADD(&ret->list, &desc->peers_permissions);
	INIT_LIST(ret->list2);
	return 0;
}

void allocation_permission_set_timer(struct allocation_permission* permission, uint32_t lifetime)
{
	struct itimerspec expire;
	struct itimerspec old;
	/* timer */
	expire.it_value.tv_sec = (long)lifetime;
	expire.it_value.tv_nsec = 0;
	expire.it_interval.tv_sec = 0; /* no interval */
	expire.it_interval.tv_nsec = 0;
	memset(&old, 0x00, sizeof(struct itimerspec));

	/* set the timer */
	if (timer_settime(permission->expire_timer, 0, &expire, &old) == -1)
	{
		return;
	}
}

struct allocation_tcp_relay* allocation_desc_find_tcp_relay_addr(struct allocation_desc* desc, int family, const uint8_t* peer_addr, uint16_t peer_port)
{
	struct list_head* get = NULL;
	struct list_head* n = NULL;
	list_iterate_safe(get, n, &desc->tcp_relays)
	{
		struct allocation_tcp_relay* tmp = list_get(get, struct allocation_tcp_relay, list);
		if (tmp->family != family)
		{
			continue;
		}

		if (!memcmp(tmp->peer_addr, peer_addr, 4) && tmp->peer_port == peer_port)
		{
			return tmp;
		}
	}
	/* not found */
	return NULL;
}


int allocation_desc_add_tcp_relay(struct allocation_desc* desc, uint32_t id,
	int peer_sock, int family, const uint8_t* peer_addr, uint16_t peer_port,
	uint32_t timeout, size_t buffer_size, uint8_t* connect_msg_id)
{
	struct allocation_tcp_relay* ret = NULL;
	struct sigevent event;

	if (!(ret = (allocation_tcp_relay*)malloc(sizeof(struct allocation_tcp_relay))))
	{
		return -1;
	}

	ret->buf = NULL;
	ret->newConnection = 0;

	/* connect_msg_id present, it means that client contact another peer
	 * and due to asynchronous connect(), server keep request ID.
	 * it also means that the current remote socket is not ready
	 * (i.e. connected) to send data
	 */
	if (connect_msg_id)
	{
		ret->ready = 0;
		memcpy(ret->connect_msg_id, connect_msg_id, 12);
	}
	else
	{
		ret->ready = 1;
	}

	ret->created = time(NULL);

	if (buffer_size)
	{
		if (!(ret->buf = (char*)malloc(sizeof(char) * buffer_size)))
		{
			free(ret);
			return -1;
		}
	}
	ret->buf_len = 0;
	ret->buf_size = buffer_size;

	ret->connection_id = id;
	ret->family = family;
	ret->peer_sock = peer_sock;
	memcpy(&ret->peer_addr, peer_addr, family == AF_INET6 ? 16 : 4);
	ret->peer_port = peer_port;

	/* client_sock will be initialized when client will send
	 * a ConnectionBind request
	 */
	ret->client_sock = NULL;

	/* timer */
	memset(&event, 0x00, sizeof(struct sigevent));
	event.sigev_value.sival_ptr = ret;
	event.sigev_notify = SIGEV_SIGNAL;
	event.sigev_signo = SIGRT_EXPIRE_TCP_RELAY;

	memset(&ret->expire_timer, 0x00, sizeof(timer_t));
	if (timer_create(CLOCK_REALTIME, &event, &ret->expire_timer) == -1)
	{
		free(ret);
		return -1;
	}

	allocation_tcp_relay_set_timer(ret, timeout);

	/* add to the list */
	LIST_ADD(&ret->list, &desc->tcp_relays);
	INIT_LIST(ret->list2);
	return 0;
}

struct allocation_tcp_relay* allocation_desc_find_tcp_relay_id(struct allocation_desc* desc, uint32_t id)
{
	struct list_head* get = NULL;
	struct list_head* n = NULL;

	list_iterate_safe(get, n, &desc->tcp_relays)
	{
		struct allocation_tcp_relay* tmp = list_get(get,
			struct allocation_tcp_relay, list);

		if (tmp->connection_id == id)
		{
			return tmp;
		}
	}

	/* not found */
	return NULL;
}


void allocation_tcp_relay_set_timer(struct allocation_tcp_relay* relay, uint32_t timeout)
{
	struct itimerspec expire;
	struct itimerspec old;

	/* start timer */
	expire.it_value.tv_sec = (long)timeout;
	expire.it_value.tv_nsec = 0;
	expire.it_interval.tv_sec = 0; /* no interval */
	expire.it_interval.tv_nsec = 0;
	memset(&old, 0x00, sizeof(struct itimerspec));

	/* set the timer */
	if (timer_settime(relay->expire_timer, 0, &expire, &old) == -1)
	{
		return;
	}
}



struct allocation_token* allocation_token_list_find(struct list_head* list, uint8_t* id)
{
	struct list_head* get = NULL;
	struct list_head* n = NULL;

	list_iterate_safe(get, n, list)
	{
		struct allocation_token* tmp = list_get(get, struct allocation_token, list);

		if (!memcmp(tmp->id, id, 8))
		{
			return tmp;
		}
	}

	/* not found */
	return NULL;
}


void allocation_token_list_remove(struct list_head* list, struct allocation_token* token)
{
	(void)list; /* not used */

	LIST_DEL(&token->list);
	allocation_token_free(&token);
}

void allocation_token_free(struct allocation_token** token)
{
	timer_delete((*token)->expire_timer);
	LIST_DEL(&(*token)->list);
	LIST_DEL(&(*token)->list2);
	free(*token);
	*token = NULL;
}
void allocation_token_set_timer(struct allocation_token* token,
	uint32_t lifetime)
{
	struct itimerspec expire;
	struct itimerspec old;

	expire.it_value.tv_sec = (long)lifetime;
	expire.it_value.tv_nsec = 0;
	expire.it_interval.tv_sec = 0; /* no interval */
	expire.it_interval.tv_nsec = 0;
	memset(&old, 0x00, sizeof(struct itimerspec));

	if (timer_settime(token->expire_timer, 0, &expire, &old) == -1)
	{
		return;
	}
}


void allocation_desc_set_timer(struct allocation_desc* desc, uint32_t lifetime)
{
	struct itimerspec expire;
	struct itimerspec old;
	/* timer */
	expire.it_value.tv_sec = (long)lifetime;
	expire.it_value.tv_nsec = 0;
	expire.it_interval.tv_sec = 0; /* no interval */
	expire.it_interval.tv_nsec = 0;
	memset(&old, 0x00, sizeof(struct itimerspec));
	/* (re)-init bandwidth quota stuff */
	gettimeofday(&desc->last_timeup, NULL);
	gettimeofday(&desc->last_timedown, NULL);
	/* set the timer */
	if (timer_settime(desc->expire_timer, 0, &expire, &old) == -1)
	{
		return;
	}
}

void allocation_list_remove(struct list_head* list, struct allocation_desc* desc)
{
	/* to avoid compilation warning */
	(void)list;

	LIST_DEL(&desc->list);
	allocation_desc_free(&desc);
}


void allocation_desc_free(struct allocation_desc** desc)
{
	struct allocation_desc* ret = *desc;
	struct list_head* get = NULL;
	struct list_head* n = NULL;

	/* delete the timer */
	timer_delete(ret->expire_timer);

	free(ret->username);

	/* free up the lists */
	list_iterate_safe(get, n, &ret->peers_channels)
	{
		struct allocation_channel* tmp = list_get(get, struct allocation_channel, list);
		timer_delete(tmp->expire_timer);
		LIST_DEL(&tmp->list);
		LIST_DEL(&tmp->list2);
		free(tmp);
	}

	list_iterate_safe(get, n, &ret->peers_permissions)
	{
		struct allocation_permission* tmp = list_get(get, struct allocation_permission, list);
		timer_delete(tmp->expire_timer);
		LIST_DEL(&tmp->list);
		LIST_DEL(&tmp->list2);
		free(tmp);
	}

	list_iterate_safe(get, n, &ret->tcp_relays)
	{
		struct allocation_tcp_relay* tmp = list_get(get, struct allocation_tcp_relay, list);
		allocation_tcp_relay_list_remove(&ret->tcp_relays, tmp);
	}

	if (ret->relayed_sock > 0)
	{
		close(ret->relayed_sock);
	}

	ret->relayed_sock = -1;

	if (ret->relayed_sock_tcp > 0)
	{
		close(ret->relayed_sock_tcp);
	}

	ret->relayed_sock_tcp = -1;
	/* the tuple sock is closed by the user-defined application */
	ret->tuple_sock = NULL;

	free(*desc);
	*desc = NULL;
}



void allocation_tcp_relay_list_remove(struct list_head* list, struct allocation_tcp_relay* relay)
{
	(void)list; /* not used */

	LIST_DEL(&relay->list);
	LIST_DEL(&relay->list2);

	/* close socket */
	if (relay->peer_sock > 0)
	{
		close(relay->peer_sock);
	}

	if (relay->client_sock > 0)
	{
		if ((tcp_socket*)relay->client_sock)
		{
			((tcp_socket*)relay->client_sock)->close();
		}
		else
		{
			((udp_socket*)relay->client_sock)->close();
		}
	}

	/* stop timer */
	timer_delete(relay->expire_timer);

	if (relay->buf)
	{
		free(relay->buf);
	}

	free(relay);
}


void allocation_list_add(struct list_head* list, struct allocation_desc* desc)
{ 
	debug(DBG_ATTR, "添加了客户端五元组:地址：%s,端口：%d \n", desc->tuple.client_addr, desc->tuple.client_port); 
	LIST_ADD_TAIL(&desc->list, list);
}


struct allocation_desc* allocation_desc_new(const uint8_t* id,
	uint8_t transport_protocol, const char* username, const unsigned char* key,
	const char* realm, const unsigned char* nonce,
	const sockaddr_storage* relayed_addr, socket_base* sock, uint32_t lifetime)
{
	struct allocation_desc* ret = NULL;
	size_t len_username = 0;
	struct sigevent event;

	if (username)
	{
		len_username = strlen(username);
	}

	if (!username || relayed_addr == NULL || sock == NULL || len_username == 0 || !id || !realm || !key || !nonce)
	{
		return NULL;
	}

	if (!(ret = (allocation_desc*)malloc(sizeof(struct allocation_desc))))
	{
		return NULL;
	}
	/* copy transaction ID */
	memcpy(ret->transaction_id, id, 12);
	/* copy authentication information */
	ret->username = (char*)malloc(len_username + 1);
	if (!ret->username)
	{
		free(ret);
		return NULL;
	}

	strncpy(ret->username, username, len_username);
	ret->username[len_username] = 0x00;
	/* 16 = MD5 length */
	memcpy(ret->key, key, 16);
	/* see protocol.c for nonce length */
	memcpy(ret->nonce, nonce, 24);
	strncpy(ret->realm, realm, sizeof(ret->realm) - 1);
	ret->realm[sizeof(ret->realm) - 1] = 0x00;
	/* initialize the 5-tuple */
	ret->tuple.transport_protocol = transport_protocol;
	 
	if (transport_protocol == IPPROTO_UDP)
	{
		udp_socket* sockeet = ((udp_socket*)sock);
		ret->tuple.client_addr = (uint8_t*)malloc(sockeet->remote_endpoint().address().to_string().size());
		memcpy(ret->tuple.client_addr, sockeet->remote_endpoint().address().to_string().data(), sockeet->remote_endpoint().address().to_string().size());
		ret->tuple.client_port = sockeet->remote_endpoint().port();

		ret->tuple.server_addr = (uint8_t*)malloc(sockeet->local_endpoint().address().to_string().size());
		memcpy(ret->tuple.server_addr, sockeet->local_endpoint().address().to_string().data(), sockeet->local_endpoint().address().to_string().size());
		ret->tuple.server_port = sockeet->local_endpoint().port();
	}
	else
	{
		tcp_socket* sockeet = ((tcp_socket*)sock);
		ret->tuple.client_addr = (uint8_t*)malloc(sockeet->remote_endpoint().address().to_string().size());
		memcpy(ret->tuple.client_addr, sockeet->remote_endpoint().address().to_string().data(), sockeet->remote_endpoint().address().to_string().size());
		ret->tuple.client_port = sockeet->remote_endpoint().port();

		ret->tuple.server_addr = (uint8_t*)malloc(sockeet->local_endpoint().address().to_string().size());
		memcpy(ret->tuple.server_addr, sockeet->local_endpoint().address().to_string().data(), sockeet->local_endpoint().address().to_string().size());
		ret->tuple.server_port = sockeet->local_endpoint().port();
	}
	/* copy relayed address */
	memcpy(&ret->relayed_addr, relayed_addr, sizeof(sockaddr_storage));

	ret->relayed_transport_protocol = IPPROTO_UDP;
	/* by default, this will be set by caller */
	ret->relayed_tls = 0;
	ret->relayed_dtls = 0;
	/* tocken bucket initialization */
	ret->bucket_capacity = 0;
	ret->bucket_tokenup = 0;
	ret->bucket_tokendown = 0;
	/* list of permissions */
	INIT_LIST(ret->peers_permissions);
	/* list of channels */
	INIT_LIST(ret->peers_channels);
	/* list of TCP relays */
	INIT_LIST(ret->tcp_relays);
	/* linked lists, second ones used when timer has expired */
	INIT_LIST(ret->list);
	INIT_LIST(ret->list2);
	/* timer */
	memset(&event, 0x00, sizeof(struct sigevent));
	event.sigev_value.sival_ptr = ret;
	event.sigev_notify = SIGEV_SIGNAL;
	event.sigev_signo = SIGRT_EXPIRE_ALLOCATION;

	memset(&ret->expire_timer, 0x00, sizeof(timer_t));
	if (timer_create(CLOCK_REALTIME, &event, &ret->expire_timer) == -1)
	{
		free(ret->username);
		free(ret);
		return NULL;
	}

	allocation_desc_set_timer(ret, lifetime);
	/* sockets */
	ret->relayed_sock = -1;
	ret->relayed_sock_tcp = -1;
	ret->tuple_sock = NULL;
	return ret;
}


void allocation_token_list_add(struct list_head* list, struct allocation_token* token)
{
	LIST_ADD(&token->list, list);
}

struct allocation_token* allocation_token_new(uint8_t* id, int sock, uint32_t lifetime)
{
	struct allocation_token* ret = NULL;
	struct sigevent event;

	if (!(ret = (allocation_token*)malloc(sizeof(struct allocation_token))))
	{
		return NULL;
	}

	memcpy(ret->id, id, 8);
	ret->sock = sock;

	memset(&event, 0x00, sizeof(struct sigevent));
	event.sigev_value.sival_ptr = ret;
	event.sigev_notify = SIGEV_SIGNAL;
	event.sigev_signo = SIGRT_EXPIRE_TOKEN;

	if (timer_create(CLOCK_REALTIME, &event, &ret->expire_timer) == -1)
	{
		free(ret);
		return NULL;
	}

	allocation_token_set_timer(ret, lifetime);

	INIT_LIST(ret->list);
	INIT_LIST(ret->list2);

	return ret;
}