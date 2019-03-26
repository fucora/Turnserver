/*
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
 

struct allocation_desc* allocation_list_find_tuple(struct list_head* list,
	int transport_protocol, const  address_type server_addr,
	const  address_type client_addr, socklen_t addr_size)
{
	struct list_head* get = NULL;
	struct list_head* n = NULL;

	list_iterate_safe(get, n, list)
	{
		struct allocation_desc* tmp = list_get(get, struct allocation_desc, list);

		if (tmp->tuple.transport_protocol == transport_protocol &&
			!memcmp(&tmp->tuple.server_addr, &server_addr, addr_size) &&
			!memcmp(&tmp->tuple.client_addr, &client_addr, addr_size))
		{
			return tmp;
		}
	}

	/* not found */
	return NULL;
}

struct allocation_channel* allocation_desc_find_channel_number(
	struct allocation_desc* desc, uint16_t channel)
{
	struct list_head* get = NULL;
	struct list_head* n = NULL;

	list_iterate_safe(get, n, &desc->peers_channels)
	{
		struct allocation_channel* tmp = list_get(get, struct allocation_channel,
			list);

		if (tmp->channel_number == channel)
		{
			return tmp;
		}
	}
}

struct allocation_channel* allocation_desc_find_channel_number(struct allocation_desc* desc, uint16_t channel)
{
	struct list_head* get = NULL;
	struct list_head* n = NULL;

	list_iterate_safe(get, n, &desc->peers_channels)
	{
		struct allocation_channel* tmp = list_get(get, struct allocation_channel,
			list);

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
		struct allocation_channel* tmp = list_get(get, struct allocation_channel,
			list);

		if (tmp->family == family && !memcmp(&tmp->peer_addr, peer_addr,
			family == AF_INET ? 4 : 16) && tmp->peer_port == peer_port)
		{
			return tmp->channel_number;
		}
	}
	/* not found */
	return 0;
}

void allocation_channel_set_timer(struct allocation_channel* channel,uint32_t lifetime)
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


int allocation_desc_add_channel(struct allocation_desc* desc, uint16_t channel,uint32_t lifetime, int family, const uint8_t* peer_addr, uint16_t peer_port)
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

 
