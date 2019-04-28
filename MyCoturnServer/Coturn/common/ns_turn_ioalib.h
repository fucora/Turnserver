/*
 * Copyright (C) 2011, 2012, 2013 Citrix Systems
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * IO Abstraction library
 */

#ifndef __IOA_LIB__
#define __IOA_LIB__

#include "ns_turn_ioaddr.h"

#ifdef __cplusplus
extern "C" {
#endif

////////////// forward declarations ////////

struct _ts_ur_super_session;
typedef struct _ts_ur_super_session ts_ur_super_session;

struct _tcp_connection;
typedef struct _tcp_connection tcp_connection;


////////////// Mutexes /////////////////////

struct _turn_mutex {
  u32bits data;
  void* mutex;
};

typedef struct _turn_mutex turn_mutex;

int turn_mutex_init(turn_mutex* mutex);
int turn_mutex_init_recursive(turn_mutex* mutex);

int turn_mutex_lock(const turn_mutex *mutex);
int turn_mutex_unlock(const turn_mutex *mutex);

int turn_mutex_destroy(turn_mutex* mutex);

#define TURN_MUTEX_DECLARE(mutex) turn_mutex mutex;
#define TURN_MUTEX_INIT(mutex) turn_mutex_init(mutex)
#define TURN_MUTEX_INIT_RECURSIVE(mutex) turn_mutex_init_recursive(mutex)
#define TURN_MUTEX_LOCK(mutex) turn_mutex_lock(mutex)
#define TURN_MUTEX_UNLOCK(mutex) turn_mutex_unlock(mutex)
#define TURN_MUTEX_DESTROY(mutex) turn_mutex_destroy(mutex)

/////// Sockets //////////////////////////////

#define IOA_EV_TIMEOUT	0x01
#define IOA_EV_READ		0x02
#define IOA_EV_WRITE	0x04
#define IOA_EV_SIGNAL	0x08
#define IOA_EV_CLOSE	0x10

enum _SOCKET_TYPE {
	UNKNOWN_SOCKET=0,
	TCP_SOCKET=6,
	UDP_SOCKET=17,
	TLS_SOCKET=56,
	SCTP_SOCKET=132,
	TLS_SCTP_SOCKET=133,
	DTLS_SOCKET=250,
	TENTATIVE_SCTP_SOCKET=254,
	TENTATIVE_TCP_SOCKET=255
};

typedef enum _SOCKET_TYPE SOCKET_TYPE;

enum _SOCKET_APP_TYPE {
	UNKNOWN_APP_SOCKET,
	CLIENT_SOCKET,
	HTTP_CLIENT_SOCKET,
	HTTPS_CLIENT_SOCKET,
	RELAY_SOCKET,
	RELAY_RTCP_SOCKET,
	TCP_CLIENT_DATA_SOCKET,
	TCP_RELAY_DATA_SOCKET,
	LISTENER_SOCKET
};

typedef enum _SOCKET_APP_TYPE SOCKET_APP_TYPE;

struct _ioa_socket;
typedef struct _ioa_socket ioa_socket;
typedef ioa_socket *ioa_socket_handle;

struct _ioa_engine;
typedef struct _ioa_engine ioa_engine;
typedef ioa_engine *ioa_engine_handle;

typedef void *ioa_timer_handle;

typedef void *ioa_network_buffer_handle;

/* event data for net event */
typedef struct _ioa_net_data {
	ioa_addr			src_addr;
	ioa_network_buffer_handle	nbh;
	int				recv_ttl;
	int				recv_tos;
} ioa_net_data;

/* Callback on TCP connection completion */
typedef void (*connect_cb)(int success, void *arg);
/* Callback on accepted socket from TCP relay endpoint */
typedef void (*accept_cb)(ioa_socket_handle s, void *arg);

////////// REALM ////////////

struct _realm_options_t;
typedef struct _realm_options_t realm_options_t;

//////// IP White/black listing ///////////

struct _ip_range {
	char str[257];
	char realm[513];
	ioa_addr_range enc;
};

typedef struct _ip_range ip_range_t;

struct _ip_range_list {
	ip_range_t *rs;
	size_t ranges_number;
};

typedef struct _ip_range_list ip_range_list_t;
 
/*
 * Network event handler callback
 * chnum parameter is just an optimisation hint -
 * the function must work correctly when chnum=0
 * (when no hint information is available).
 */
typedef void (*ioa_net_event_handler)(ioa_socket_handle s, int event_type, ioa_net_data *data, void *ctx, int can_resume);

/*
 * Timer callback
 */
typedef void (*ioa_timer_event_handler)(ioa_engine_handle e, void *ctx);

/* timers */
 
#define IOA_EVENT_DEL(E) do { if(E) { delete_ioa_timer(E); E = NULL; } } while(0)
 
int get_default_protocol_port(const char* scheme, size_t slen);

///////////// HTTP ////////////////////
  
///////////////////////////////////////

#ifdef __cplusplus
}
#endif

#endif /* __IOA_LIB__ */
