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

 
